#!/usr/bin/env python3
"""
NucleiSniper: rank Nuclei templates by relevance to HTTP/HTTPS targets using TypeSafe Jev,
then run Nuclei with the highest-scoring templates first.

Pipeline:
  1. Fetch each target URL concurrently (--playwright for SPAs) and build a compact profile.
  2. Index the local Nuclei YAML templates once (cached in SQLite).
  3. Send template batches to TypeSafe Jev as Score questions. Batches from every URL share
     one thread pool.
  4. Print/save templates ranked by relevance, per URL.
  5. Run Nuclei per URL with every scored template, highest score first. Jev decides
     priority, not inclusion. Skip this step with --no-scan.

Environment:
  TYPESAFE_API_KEY=...

Example:
  python NucleiSniper.py https://a.example https://b.example \
      --templates ~/nuclei-templates \
      --output relevance.json

  # score only, then scan later from the saved report
  python NucleiSniper.py --urls-file urls.txt -t ~/nuclei-templates --no-scan -o relevance.json
  python NucleiSniper.py --report relevance.json --severity critical,high
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html as _html_mod
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

import requests
import yaml
from bs4 import BeautifulSoup, Comment

# Optional: pip install tqdm for a progress bar during Jev scoring
try:
    from tqdm import tqdm as _tqdm  # type: ignore[import-untyped]
except ImportError:
    _tqdm = None


TYPESAFE_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"

RELEVANCE_RUBRIC = [
    "Not relevant: the observed target provides no meaningful evidence for the product, component, protocol, endpoint, or condition this template concerns.",
    "Weak relevance: only generic or indirect evidence exists; the template is possible but poorly supported by the observed target.",
    "Plausible: there is some evidence matching the template's technology, product, endpoint, or behavior, but important evidence is still missing.",
    "Relevant: the observed target contains good evidence that the template applies to this product, component, protocol, endpoint, or behavior.",
    "Highly relevant: direct or strong evidence closely matches the specific product, component, endpoint, version family, or behavior checked by the template.",
]

INTERESTING_HEADERS = {
    "server",
    "x-powered-by",
    "x-generator",
    "x-aspnet-version",
    "x-runtime",
    "via",
    "cf-ray",
    "x-drupal-cache",
    "x-magento-cache-debug",
    "x-jenkins",
    "x-grafana-version",
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "x-cache",
    "x-cache-status",
    "x-varnish",
    "x-cdn",
    "x-amz-cf-id",
    "x-azure-ref",
    "x-request-id",
    "x-correlation-id",
    "x-envoy-upstream-service-time",
    "x-redirect-by",
    "x-litespeed-cache",
    "x-turbo-charged-by",
    "x-permitted-cross-domain-policies",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
    "nel",
    "report-to",
    "expect-ct",
    "www-authenticate",
    "x-pingback",
}

PROTOCOL_KEYS = {
    "http",
    "network",
    "dns",
    "ssl",
    "websocket",
    "headless",
    "file",
    "code",
    "javascript",
    "whois",
}


@dataclass
class TemplateSummary:
    key: str
    template_id: str
    name: str
    description: str
    severity: str
    tags: list[str]
    protocols: list[str]
    classification: dict[str, Any]
    path_hints: list[str]
    matcher_words: list[str]
    file_path: str
    search_text: str


@dataclass
class RankedTemplate:
    template_id: str
    name: str
    file_path: str
    score: float
    confidence: float
    probabilities: dict[str, float]
    severity: str
    tags: list[str]


def truncate(value: Any, max_len: int) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


class TokenLimitError(RuntimeError):
    pass


def csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip().lower() for part in value.split(",") if part.strip()}


def parse_headers(items: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items or []:
        if ":" not in item:
            raise ValueError(f"Header must look like 'Name: Value': {item}")
        name, value = item.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"Header is missing a name: {item}")
        headers[name] = value.strip()
    return headers


def apply_template_filters(
    templates: list[TemplateSummary],
    severities: set[str],
    tags: set[str],
    exclude_tags: set[str],
    protocols: set[str],
) -> list[TemplateSummary]:
    selected: list[TemplateSummary] = []
    for template in templates:
        if severities and template.severity.lower() not in severities:
            continue
        template_tags = {tag.lower() for tag in template.tags}
        if tags and not (template_tags & tags):
            continue
        if exclude_tags and (template_tags & exclude_tags):
            continue
        template_protocols = {protocol.lower() for protocol in template.protocols}
        if protocols and not (template_protocols & protocols):
            continue
        selected.append(template)
    return selected


PREFILTER_ALWAYS_KEEP = {"dast", "dns", "headless", "ssl"}
PREFILTER_SYNONYMS = {"httpd": "apache", "rxss": "xss", "sqli": "sql"}
GENERIC_TAG_THRESHOLD = 300


def prefilter_templates(
    templates: list[TemplateSummary],
    target: dict[str, Any],
    no_prefilter: bool = False,
) -> list[TemplateSummary]:
    """Drop templates that cannot possibly match the target before sending to Jev AI.

    Removes code/file-protocol templates (they never scan URLs), then uses
    tag-based matching: templates whose product-specific tags do not appear
    anywhere in the target profile are dropped.  Generic templates (only
    high-frequency tags) and always-relevant protocol tags pass through.
    """
    if no_prefilter:
        return templates

    # Step 1: drop code/file protocol templates (they never scan URLs)
    url_templates = [
        t for t in templates
        if not ({"code", "file"} & {p.lower() for p in t.protocols})
    ]

    # Step 2: build haystack from the full target profile
    haystack = json.dumps(target).lower()

    # Step 3: compute tag frequencies to identify generic (category) tags
    tag_counts: dict[str, int] = {}
    for t in url_templates:
        for tag in t.tags:
            lower = tag.lower()
            tag_counts[lower] = tag_counts.get(lower, 0) + 1
    generic_tags = {tag for tag, count in tag_counts.items() if count >= GENERIC_TAG_THRESHOLD}

    # Step 4: keep templates whose product tags match the target
    kept: list[TemplateSummary] = []
    for t in url_templates:
        lower_tags = {tag.lower() for tag in t.tags}

        # Always keep templates tagged with always-relevant protocols
        if lower_tags & PREFILTER_ALWAYS_KEEP:
            kept.append(t)
            continue

        # Product tags = all tags minus generic ones
        product_tags = lower_tags - generic_tags

        # Templates with no product-specific tags are generic; keep them
        if not product_tags:
            kept.append(t)
            continue

        # Check if any product tag (or its synonym) appears in the haystack
        matched = False
        for tag in product_tags:
            if tag in haystack:
                matched = True
                break
            synonym = PREFILTER_SYNONYMS.get(tag)
            if synonym and synonym in haystack:
                matched = True
                break

        if matched:
            kept.append(t)

    print(
        f"[prefilter] kept {len(kept)}/{len(templates)} templates for this target",
        file=sys.stderr,
    )
    return kept


def host_slug(url: str) -> str:
    parsed = urlparse(url)
    raw = f"{parsed.netloc}{parsed.path}"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("_")
    return (safe or "url")[:150]


def report_filename(url: str) -> str:
    return f"{host_slug(url)}.json"


def unique(items: Iterable[str], limit: int | None = None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        item = str(raw).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if limit is not None and len(out) >= limit:
            break
    return out


def ensure_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Target must start with http:// or https://: {url}")
    if not parsed.netloc:
        raise ValueError(f"Target URL is missing a hostname: {url}")
    return url


def collect_urls(positional: list[str], urls_file: Path | None) -> list[str]:
    raw = list(positional)
    if urls_file is not None:
        text = urls_file.read_text(encoding="utf-8-sig")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raw.append(line)

    urls: list[str] = []
    seen: set[str] = set()
    for item in raw:
        url = ensure_url(item)
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    if not urls:
        raise ValueError("Provide at least one target URL or --urls-file")
    return urls


def profile_url_job(
    url: str,
    timeout: float,
    insecure: bool,
    max_body: int,
    browser: Any = None,
    render_wait: float = 0.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, dict[str, Any] | None, str | None, float]:
    started = time.perf_counter()
    try:
        if browser is None:
            target = profile_target(url, timeout, insecure, max_body, proxy, extra_headers)
        else:
            target = profile_rendered(
                browser, url, timeout, insecure, max_body, render_wait, user_agent, proxy, extra_headers
            )
        return url, target, None, time.perf_counter() - started
    except Exception as exc:
        return url, None, str(exc), time.perf_counter() - started


def round_robin(items: list[str], buckets: int) -> list[list[str]]:
    count = min(buckets, len(items))
    groups: list[list[str]] = [[] for _ in range(count)]
    for index, item in enumerate(items):
        groups[index % count].append(item)
    return groups


def profile_urls_with_browser(
    urls: list[str],
    timeout: float,
    insecure: bool,
    max_body: int,
    render_wait: float,
    executable_path: str | None = None,
    proxy: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[tuple[str, dict[str, Any] | None, str | None, float]]:
    # One browser per worker thread. Playwright sync objects cannot cross threads.
    from playwright.sync_api import sync_playwright

    playwright = sync_playwright().start()
    try:
        launch_args: dict[str, Any] = {
            "headless": True,
            "args": ["--disable-blink-features=AutomationControlled"],
        }
        if executable_path:
            launch_args["executable_path"] = executable_path
        browser = playwright.chromium.launch(**launch_args)
        try:
            user_agent = chrome_user_agent(browser)
            return [
                profile_url_job(
                    url,
                    timeout,
                    insecure,
                    max_body,
                    browser,
                    render_wait,
                    user_agent,
                    proxy,
                    extra_headers,
                )
                for url in urls
            ]
        finally:
            browser.close()
    finally:
        playwright.stop()


def infer_technologies(html: str, headers: dict[str, str], cookies: list[str]) -> list[str]:
    haystack = "\n".join(
        [html[:250_000], json.dumps(headers, ensure_ascii=False), " ".join(cookies)]
    ).lower()

    fingerprints = {
        # CMS
        "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
        "Elementor": ["/elementor/", "elementor-"],
        "Drupal": ["drupal-settings-json", "/sites/default/files/", "x-drupal-cache"],
        "Joomla": ["joomla!", "/media/system/js/", "com_content"],
        "Magento": ["magento", "mage-cache", "x-magento"],
        "Shopify": ["shopify", "cdn.shopify.com", "myshopify"],
        "Wix": ["wix.com", "x-wix-"],
        "Squarespace": ["squarespace", "static.squarespace.com"],
        "Ghost": ["ghost-powered", "ghost.org"],
        "Typo3": ["typo3", "typo3conf"],
        "PrestaShop": ["prestashop", "presta-"],
        "Moodle": ["moodle", "/mod/"],
        "MediaWiki": ["mediawiki", "wgaction"],
        "Confluence": ["confluence", "ajs-remote-user"],
        "Bitbucket": ["bitbucket"],
        "HubSpot": ["hubspot", "hs-analytics", "hbspt"],
        "Webflow": ["webflow", "wf-page"],
        "Contentful": ["contentful"],
        # Frameworks
        "Jenkins": ["x-jenkins", "jenkins"],
        "Grafana": ["grafana", "x-grafana-version"],
        "Kibana": ["kibana"],
        "Next.js": ["__next_data__", "/_next/static/", "__next"],
        "Nuxt.js": ["__nuxt", "/_nuxt/"],
        "React": ["reactroot", "react-dom", "data-reactroot", "_reactlistening"],
        "Angular": ["ng-version", "angular.js", "angular.min.js", "ng-app"],
        "Vue.js": ["vue.js", "vue.min.js", "__vue__", "vue-router"],
        "Svelte": ["__svelte", "svelte"],
        "Laravel": ["laravel_session", "laravel"],
        "ASP.NET": ["asp.net", "aspnet", "__viewstate", "__eventvalidation"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "Flask": ["werkzeug", "flask"],
        "Ruby on Rails": ["x-runtime", "csrf-token", "_rails_", "turbolinks"],
        "Spring": ["jsessionid", "spring", "x-application-context"],
        "Express": ["express", "x-powered-by\": \"express"],
        "FastAPI": ["fastapi"],
        "Symfony": ["symfony", "sf-toolbar"],
        "CodeIgniter": ["codeigniter", "ci_session"],
        "CakePHP": ["cakephp"],
        "Struts": ["struts", ".action", ".do"],
        # Web servers / proxies
        "PHP": ["phpsessid", "x-powered-by\": \"php", ".php"],
        "nginx": ["server\": \"nginx", "nginx/"],
        "Apache": ["server\": \"apache", "apache/"],
        "IIS": ["server\": \"microsoft-iis", "x-aspnet-version", "asp.net"],
        "LiteSpeed": ["litespeed", "x-litespeed"],
        "Caddy": ["server\": \"caddy"],
        "Tomcat": ["tomcat", "catalina"],
        "Jetty": ["server\": \"jetty"],
        "OpenResty": ["openresty"],
        "Envoy": ["x-envoy-upstream-service-time", "envoy"],
        "HAProxy": ["haproxy"],
        "Traefik": ["traefik"],
        # CDN / cloud
        "Cloudflare": ["cf-ray", "cloudflare"],
        "AWS": ["x-amz-", "amazonaws.com", "awselb"],
        "Azure": ["x-azure-ref", "windows.net", "azurewebsites.net"],
        "Google Cloud": ["x-cloud-trace-context", "appspot.com"],
        "Fastly": ["x-served-by", "fastly"],
        "Akamai": ["akamai", "x-akamai"],
        "Vercel": ["x-vercel-id", "vercel"],
        "Netlify": ["x-nf-request-id", "netlify"],
        "Heroku": ["heroku"],
        # Databases (exposed in errors/headers)
        "MySQL": ["mysql", "mariadb"],
        "PostgreSQL": ["postgresql", "pgsql"],
        "MongoDB": ["mongodb"],
        "Redis": ["redis"],
        "Elasticsearch": ["elasticsearch", "x-elastic-product"],
        "CouchDB": ["couchdb"],
        "Cassandra": ["cassandra"],
        # Auth / identity
        "Keycloak": ["keycloak"],
        "Okta": ["okta"],
        "Auth0": ["auth0"],
        "SAML": ["samlrequest", "saml"],
        "OAuth": ["oauth", "access_token", "client_id"],
        "JWT": ["eyj", "jwt"],
        # DevOps / monitoring
        "Prometheus": ["prometheus"],
        "SonarQube": ["sonarqube", "sonar"],
        "GitLab": ["gitlab"],
        "Gitea": ["gitea"],
        "Nagios": ["nagios"],
        "Zabbix": ["zabbix"],
        "Splunk": ["splunk"],
        "Docker": ["docker"],
        "Kubernetes": ["kubernetes", "k8s"],
        # Panels / admin
        "cPanel": ["cpanel"],
        "Plesk": ["plesk"],
        "phpMyAdmin": ["phpmyadmin"],
        "Adminer": ["adminer"],
        "Webmin": ["webmin"],
        # API / docs
        "Swagger": ["swagger", "swagger-ui"],
        "GraphQL": ["graphql", "__schema"],
        "gRPC": ["grpc"],
        # Mail
        "Roundcube": ["roundcube"],
        "Zimbra": ["zimbra"],
        "Microsoft Exchange": ["/owa/", "x-owa-version", "outlook web app", "/ecp/"],
        # Networking / IoT
        "Fortinet": ["fortinet", "fortigate", "fortimail"],
        "Palo Alto": ["paloalto", "globalprotect"],
        "SonicWall": ["sonicwall"],
        "Cisco": ["cisco"],
        "MikroTik": ["mikrotik", "routeros"],
        "Ubiquiti": ["ubiquiti", "unifi"],
    }

    detected: list[str] = []
    for tech, needles in fingerprints.items():
        if any(needle in haystack for needle in needles):
            detected.append(tech)
    return detected


def mmh3_hash(data: bytes) -> int:
    """Simplified MurmurHash3 32-bit for favicon hashing (matches Shodan/Nuclei convention)."""
    import base64
    encoded = base64.encodebytes(data)
    # MurmurHash3 32-bit
    c1, c2, seed = 0xCC9E2D51, 0x1B873593, 0
    h = seed
    length = len(encoded)
    nblocks = length // 4
    for i in range(nblocks):
        k = struct.unpack_from("<I", encoded, i * 4)[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail_idx = nblocks * 4
    k = 0
    tail_size = length & 3
    if tail_size >= 3:
        k ^= encoded[tail_idx + 2] << 16
    if tail_size >= 2:
        k ^= encoded[tail_idx + 1] << 8
    if tail_size >= 1:
        k ^= encoded[tail_idx]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    if h & 0x80000000:
        h -= 0x100000000
    return h


def fetch_favicon_hash(base_url: str, session: requests.Session, timeout: float) -> int | None:
    """Fetch /favicon.ico and return its mmh3 hash (Shodan-compatible)."""
    try:
        resp = session.get(urljoin(base_url, "/favicon.ico"), timeout=timeout, allow_redirects=True)
        if resp.status_code == 200 and len(resp.content) > 0 and len(resp.content) < 2_000_000:
            return mmh3_hash(resp.content)
    except Exception:
        pass
    return None


def fetch_robots_sitemap(base_url: str, session: requests.Session, timeout: float) -> dict[str, Any]:
    """Fetch robots.txt and sitemap.xml, extract paths and directives."""
    result: dict[str, Any] = {}
    try:
        resp = session.get(urljoin(base_url, "/robots.txt"), timeout=timeout)
        if resp.status_code == 200 and "text" in resp.headers.get("content-type", ""):
            lines = resp.text.splitlines()[:200]
            disallowed: list[str] = []
            sitemaps: list[str] = []
            for line in lines:
                lower = line.strip().lower()
                if lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                elif lower.startswith("sitemap:"):
                    url = line.split(":", 1)[1].strip()
                    if url:
                        sitemaps.append(url)
            if disallowed:
                result["robots_disallowed"] = disallowed[:50]
            if sitemaps:
                result["sitemaps"] = sitemaps[:10]
    except Exception:
        pass
    try:
        resp = session.get(urljoin(base_url, "/sitemap.xml"), timeout=timeout)
        if resp.status_code == 200 and len(resp.text) < 500_000:
            paths = re.findall(r"<loc>(.+?)</loc>", resp.text)[:100]
            if paths:
                result["sitemap_urls"] = paths
    except Exception:
        pass
    return result


def get_ssl_info(hostname: str, port: int = 443) -> dict[str, Any] | None:
    """Extract TLS certificate details. A failed verification is reported, since self-signed or
    mismatched certificates are themselves useful evidence (appliances, admin panels, dev hosts)."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, port))
            cert: Any = s.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return {"verified": False, "verify_error": truncate(exc.verify_message or exc, 300)}
    except Exception:
        return None
    try:
        if not cert:
            return None
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        san_entries = [entry[1] for entry in cert.get("subjectAltName", ())]
        return {
            "verified": True,
            "cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", ""),
            "not_before": cert.get("notBefore", ""),
            "not_after": cert.get("notAfter", ""),
            "san": san_entries[:30],
        }
    except Exception:
        return None


def get_dns_records(hostname: str) -> dict[str, list[str]] | None:
    """Resolve basic DNS records. Returns CNAME and A records using stdlib only."""
    records: dict[str, list[str]] = {}
    try:
        # gethostbyname_ex follows the CNAME chain; getfqdn would do a reverse (PTR) lookup instead.
        canonical, _aliases, _ips = socket.gethostbyname_ex(hostname)
        if canonical and canonical.lower() != hostname.lower():
            records["cname"] = [canonical]
    except Exception:
        pass
    try:
        addrs = socket.getaddrinfo(hostname, None)
        ips = list({addr[4][0] for addr in addrs})[:10]
        if ips:
            records["a_aaaa"] = ips
    except Exception:
        pass
    return records if records else None


def probe_error_page(base_url: str, session: requests.Session, timeout: float) -> dict[str, Any] | None:
    """Fetch a guaranteed 404 and extract fingerprinting info from the error page."""
    try:
        url = urljoin(base_url, f"/jev_nonexistent_{int(time.time())}")
        resp = session.get(url, timeout=timeout, allow_redirects=False)
        result: dict[str, Any] = {"status_code": resp.status_code}
        body = resp.text[:3000]
        if body:
            result["body_excerpt"] = body
        server = resp.headers.get("server", "")
        if server:
            result["server"] = server
        return result
    except Exception:
        return None


COMMON_PROBES = [
    "/.git/HEAD",
    "/.env",
    "/.DS_Store",
    "/wp-login.php",
    "/wp-admin/",
    "/administrator/",
    "/actuator/health",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger-ui.html",
    "/swagger/v1/swagger.json",
    "/.well-known/openid-configuration",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/elmah.axd",
    "/web.config",
    "/.htaccess",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/info.php",
    "/debug/pprof/",
    "/metrics",
    "/health",
    "/status",
    "/console",
]


def probe_common_paths(base_url: str, session: requests.Session, timeout: float) -> list[dict[str, Any]]:
    """Probe well-known paths and report which ones exist (non-404)."""
    found: list[dict[str, Any]] = []
    for path in COMMON_PROBES:
        try:
            resp = session.get(urljoin(base_url, path), timeout=timeout, allow_redirects=False)
            if resp.status_code not in {404, 410, 403}:
                found.append({"path": path, "status": resp.status_code, "size": len(resp.content)})
        except Exception:
            continue
    return found


def extract_meta_tags(soup: BeautifulSoup) -> dict[str, str]:
    """Extract interesting <meta> tags: generator, application-name, og:*, etc."""
    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        name = (tag.get("name") or tag.get("property") or "").lower()
        content = tag.get("content", "")
        if not name or not content:
            continue
        if name in {
            "generator", "application-name", "author", "framework",
            "og:site_name", "og:type", "og:title",
            "twitter:site", "twitter:creator",
            "powered-by", "csrf-param",
        }:
            meta[name] = content[:300]
    return meta


WELL_KNOWN_PROBES = [
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/nodeinfo",
]

MANIFEST_PATHS = ["/manifest.json", "/manifest.webmanifest", "/site.webmanifest"]
SERVICE_WORKER_PATHS = ["/sw.js", "/service-worker.js"]


def probe_well_known(base_url: str, session: requests.Session, timeout: float) -> list[dict[str, Any]]:
    """Probe /.well-known/ endpoints and return those that responded."""
    found: list[dict[str, Any]] = []
    for path in WELL_KNOWN_PROBES:
        try:
            resp = session.get(urljoin(base_url, path), timeout=timeout, allow_redirects=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                found.append({
                    "path": path,
                    "size": len(resp.content),
                    "excerpt": truncate(resp.text, 500),
                })
        except Exception:
            continue
    return found


def probe_manifest(base_url: str, session: requests.Session, timeout: float) -> dict[str, Any] | None:
    """Try to fetch manifest.json and extract useful fields."""
    for path in MANIFEST_PATHS:
        try:
            resp = session.get(urljoin(base_url, path), timeout=timeout, allow_redirects=True)
            if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                data = resp.json()
                result: dict[str, Any] = {}
                for key in ("name", "short_name", "start_url", "display", "theme_color", "scope"):
                    if key in data:
                        result[key] = str(data[key])[:200]
                if result:
                    return result
        except Exception:
            continue
    return None


def probe_service_worker(base_url: str, session: requests.Session, timeout: float) -> str | None:
    """Check if a service worker script exists and return a snippet."""
    for path in SERVICE_WORKER_PATHS:
        try:
            resp = session.get(urljoin(base_url, path), timeout=timeout, allow_redirects=False)
            if resp.status_code == 200 and "javascript" in resp.headers.get("content-type", ""):
                return truncate(resp.text, 1000)
        except Exception:
            continue
    return None


def probe_options(base_url: str, session: requests.Session, timeout: float) -> list[str] | None:
    """Send an OPTIONS request and return the allowed HTTP methods."""
    try:
        resp = session.options(base_url, timeout=timeout)
        allow = resp.headers.get("allow", "")
        if allow:
            return [m.strip().upper() for m in allow.split(",") if m.strip()]
    except Exception:
        pass
    return None


JS_GLOBALS_SCRIPT = """
(() => {
    const found = [];
    const checks = {
        'Next.js': () => !!window.__NEXT_DATA__,
        'Nuxt.js': () => !!window.__NUXT__,
        'Vue.js': () => !!window.__VUE__,
        'Svelte': () => !!window.__svelte,
        'React': () => !!document.querySelector('[data-reactroot]') || !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__,
        'Angular': () => !!window.ng || !!document.querySelector('[ng-version]'),
        'jQuery': () => !!window.jQuery || !!window.$,
        'Ember': () => !!window.Ember,
        'Backbone': () => !!window.Backbone,
        'Gatsby': () => !!window.___gatsby,
        'Remix': () => !!window.__remixContext,
        'WordPress': () => !!window.wp,
        'Drupal': () => !!window.Drupal,
        'Shopify': () => !!window.Shopify,
        'Webflow': () => !!window.Webflow,
    };
    for (const [name, check] of Object.entries(checks)) {
        try { if (check()) found.push(name); } catch {}
    }
    return found;
})()
"""


_VERSION_RE = re.compile(
    r"(?:^|[/\-_.@])([a-zA-Z][a-zA-Z0-9._-]*)[/\-_@](\d+(?:\.\d+){1,4})(?:[.\-_](?:min|slim|bundle))?\.(?:js|css|woff2?|ttf|eot|svg)",
)


def extract_asset_versions(urls: list[str]) -> list[str]:
    """Pull library-version pairs from JS/CSS asset filenames."""
    found: list[str] = []
    seen: set[str] = set()
    for u in urls:
        path = urlparse(u).path
        match = _VERSION_RE.search(path)
        if match:
            pair = f"{match.group(1)}/{match.group(2)}"
            if pair not in seen:
                seen.add(pair)
                found.append(pair)
    if len(found) > 60:
        found = found[:60]
    return found


def profile_document(
    url: str,
    final_url: str,
    status_code: int,
    content_type: str,
    header_items: Iterable[tuple[str, str]],
    cookie_names: list[str],
    html: str,
    fetch: str,
) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")

    title = ""
    if soup.title and soup.title.string:
        title = truncate(soup.title.string, 250)

    scripts = unique(
        [urljoin(final_url, tag.get("src")) for tag in soup.find_all("script") if tag.get("src")],
        limit=100,
    )
    links = unique(
        [urljoin(final_url, tag.get("href")) for tag in soup.find_all("a") if tag.get("href")],
        limit=150,
    )

    # --- #3 Stylesheet URLs ---
    stylesheets = unique(
        [
            urljoin(final_url, tag.get("href"))
            for tag in soup.find_all("link")
            if (tag.get("rel") or [""])[0].lower() == "stylesheet" and tag.get("href")
        ],
        limit=60,
    )

    # --- #4 Iframe sources ---
    iframes = unique(
        [urljoin(final_url, tag.get("src")) for tag in soup.find_all("iframe") if tag.get("src")],
        limit=30,
    )

    # --- #2 Inline script snippets (config objects, API endpoints, SDK versions) ---
    inline_scripts: list[str] = []
    for tag in soup.find_all("script"):
        if not tag.get("src") and tag.string:
            snippet = tag.string.strip()
            if len(snippet) > 20:
                inline_scripts.append(truncate(snippet, 800))
        if len(inline_scripts) >= 20:
            break

    # --- #1 HTML comments ---
    html_comments: list[str] = []
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(comment).strip()
        if len(text) > 3:
            html_comments.append(truncate(text, 500))
        if len(html_comments) >= 30:
            break
    forms: list[dict[str, Any]] = []
    for form in soup.find_all("form")[:30]:
        inputs = unique(
            [
                str(inp.get("name") or inp.get("type") or "")
                for inp in form.find_all(["input", "textarea", "select"])
            ],
            limit=30,
        )
        forms.append(
            {
                "method": str(form.get("method") or "GET").upper(),
                "action": urljoin(final_url, str(form.get("action") or "")),
                "inputs": inputs,
            }
        )

    interesting_headers = {
        key.lower(): truncate(value, 500)
        for key, value in header_items
        if key.lower() in INTERESTING_HEADERS
    }
    cookies = unique(cookie_names, limit=50)

    # Give Jev useful raw evidence without sending the whole document.
    interesting_paths = unique(
        [urlparse(x).path for x in scripts + links if urlparse(x).path],
        limit=180,
    )

    text_excerpt = truncate(soup.get_text(" ", strip=True), 4000)
    detected_technologies = infer_technologies(html, interesting_headers, cookies)
    meta_tags = extract_meta_tags(soup)

    # --- #5 Version strings from asset filenames ---
    all_asset_urls = scripts + stylesheets
    asset_versions = extract_asset_versions(all_asset_urls)

    return {
        "requested_url": url,
        "final_url": final_url,
        "status_code": status_code,
        "content_type": content_type,
        "title": title,
        "headers": interesting_headers,
        "cookies": cookies,
        "detected_technologies": detected_technologies,
        "meta_tags": meta_tags,
        "script_urls": scripts,
        "stylesheet_urls": stylesheets,
        "iframe_sources": iframes,
        "inline_scripts": inline_scripts,
        "html_comments": html_comments,
        "asset_versions": asset_versions,
        "observed_paths": interesting_paths,
        "forms": forms,
        "text_excerpt": text_excerpt,
        "fetch": fetch,
    }


def profile_target(
    url: str,
    timeout: float,
    insecure: bool,
    max_body: int,
    proxy: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    headers = {
        "User-Agent": "Jev-Nuclei-Relevance-POC/0.1",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    if extra_headers:
        headers.update(extra_headers)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    session = requests.Session()
    session.headers.update(headers)
    session.verify = False
    if proxies:
        session.proxies.update(proxies)

    response = session.get(url, timeout=timeout, allow_redirects=True)
    response_time = response.elapsed.total_seconds()
    body_bytes = response.content[:max_body]
    encoding = response.encoding or "utf-8"
    html = body_bytes.decode(encoding, errors="replace")
    target = profile_document(
        url,
        response.url,
        response.status_code,
        response.headers.get("content-type", ""),
        response.headers.items(),
        list(response.cookies.keys()),
        html,
        "requests",
    )

    # --- #10 HTTP response time ---
    target["response_time_seconds"] = round(response_time, 3)

    # --- #6 Redirect chain ---
    if response.history:
        target["redirect_chain"] = [
            {"url": r.url, "status": r.status_code}
            for r in response.history
        ]

    # --- #7 Full cookie attributes ---
    cookie_details: list[dict[str, Any]] = []
    for cookie in session.cookies:
        entry: dict[str, Any] = {"name": cookie.name, "domain": cookie.domain, "path": cookie.path}
        if cookie.secure:
            entry["secure"] = True
        if cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"):
            entry["httponly"] = True
        if cookie.has_nonstandard_attr("SameSite"):
            entry["samesite"] = cookie.get_nonstandard_attr("SameSite")
        if cookie.expires:
            entry["persistent"] = True
        cookie_details.append(entry)
    if cookie_details:
        target["cookie_details"] = cookie_details

    base_url = response.url
    parsed = urlparse(base_url)

    favicon_hash = fetch_favicon_hash(base_url, session, timeout)
    if favicon_hash is not None:
        target["favicon_hash"] = favicon_hash

    robots_sitemap = fetch_robots_sitemap(base_url, session, timeout)
    if robots_sitemap:
        target.update(robots_sitemap)

    # Raw TLS socket cannot go through an HTTP proxy, so skip it rather than bypass --proxy.
    if parsed.scheme == "https" and not proxy:
        ssl_info = get_ssl_info(parsed.hostname or "", parsed.port or 443)
        if ssl_info:
            target["ssl_certificate"] = ssl_info

    dns_info = get_dns_records(parsed.hostname or "")
    if dns_info:
        target["dns_records"] = dns_info

    error_page = probe_error_page(base_url, session, timeout)
    if error_page:
        target["error_page"] = error_page

    probed = probe_common_paths(base_url, session, timeout)
    if probed:
        target["probed_paths"] = probed

    # --- #9 .well-known probes ---
    well_known = probe_well_known(base_url, session, timeout)
    if well_known:
        target["well_known"] = well_known

    # --- #8 manifest.json / service-worker ---
    manifest = probe_manifest(base_url, session, timeout)
    if manifest:
        target["manifest"] = manifest
    sw_snippet = probe_service_worker(base_url, session, timeout)
    if sw_snippet:
        target["service_worker_snippet"] = sw_snippet

    # --- #11 OPTIONS allowed methods ---
    allowed_methods = probe_options(base_url, session, timeout)
    if allowed_methods:
        target["allowed_methods"] = allowed_methods

    return target


def chrome_user_agent(browser: Any) -> str:
    context = browser.new_context()
    try:
        page = context.new_page()
        user_agent = str(page.evaluate("() => navigator.userAgent"))
    finally:
        context.close()
    return user_agent.replace("HeadlessChrome", "Chrome")


def profile_rendered(
    browser: Any,
    url: str,
    timeout: float,
    insecure: bool,
    max_body: int,
    render_wait: float,
    user_agent: str | None = None,
    proxy: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    context_args: dict[str, Any] = {
        "ignore_https_errors": True,
        "user_agent": user_agent,
        "viewport": {"width": 1366, "height": 768},
    }
    if extra_headers:
        context_args["extra_http_headers"] = extra_headers
    if proxy:
        context_args["proxy"] = {"server": proxy}
    context = browser.new_context(**context_args)
    page = context.new_page()
    page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        nav_timeout = max(int(timeout * 1000), 1000)
        response = None
        nav_start = time.perf_counter()
        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout)
        except PlaywrightTimeout:
            if page.url in {"", "about:blank"}:
                raise
        nav_elapsed = time.perf_counter() - nav_start
        if render_wait > 0:
            page.wait_for_timeout(int(render_wait * 1000))
        html = None
        content_error: Exception | None = None
        for _ in range(4):
            try:
                page.wait_for_load_state("domcontentloaded", timeout=nav_timeout)
                html = page.content()
                break
            except Exception as exc:
                content_error = exc
                page.wait_for_timeout(500)
        if html is None:
            raise content_error or RuntimeError(f"Could not read rendered HTML for {url}")
        raw = html.encode("utf-8")[:max_body]
        html = raw.decode("utf-8", errors="replace")
        header_items = list(response.headers.items()) if response is not None else []
        content_type = response.headers.get("content-type", "") if response is not None else ""
        status_code = response.status if response is not None else 0
        cookie_names = [cookie["name"] for cookie in context.cookies()]
        target = profile_document(
            url,
            page.url,
            status_code,
            content_type,
            header_items,
            cookie_names,
            html,
            "playwright",
        )

        # --- #10 HTTP response time ---
        target["response_time_seconds"] = round(nav_elapsed, 3)

        # --- #6 Redirect chain (Playwright: final_url != requested_url implies redirects) ---
        if page.url != url:
            target["redirect_chain"] = [{"from": url, "to": page.url}]

        # --- #7 Full cookie attributes (Playwright gives rich cookie dicts) ---
        raw_cookies = context.cookies()
        if raw_cookies:
            cookie_details: list[dict[str, Any]] = []
            for c in raw_cookies:
                entry: dict[str, Any] = {"name": c["name"], "domain": c.get("domain", ""), "path": c.get("path", "/")}
                if c.get("secure"):
                    entry["secure"] = True
                if c.get("httpOnly"):
                    entry["httponly"] = True
                if c.get("sameSite") and c["sameSite"] != "None":
                    entry["samesite"] = c["sameSite"]
                if c.get("expires", -1) > 0:
                    entry["persistent"] = True
                cookie_details.append(entry)
            target["cookie_details"] = cookie_details

        # JS globals detection (Playwright-only)
        try:
            js_techs = page.evaluate(JS_GLOBALS_SCRIPT)
            if js_techs:
                existing = set(target.get("detected_technologies", []))
                for tech in js_techs:
                    if tech not in existing:
                        target.setdefault("detected_technologies", []).append(tech)
                target["js_detected_technologies"] = js_techs
        except Exception:
            pass

        # Enrich with extra probes using requests (favicon, robots, ssl, dns, error, paths)
        parsed = urlparse(page.url)
        base_url = page.url
        session = requests.Session()
        session.headers.update({"User-Agent": user_agent or "Jev-Nuclei-Relevance-POC/0.1"})
        session.verify = False
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})
        probe_timeout = min(timeout, 8.0)

        favicon_hash = fetch_favicon_hash(base_url, session, probe_timeout)
        if favicon_hash is not None:
            target["favicon_hash"] = favicon_hash

        robots_sitemap = fetch_robots_sitemap(base_url, session, probe_timeout)
        if robots_sitemap:
            target.update(robots_sitemap)

        # Raw TLS socket cannot go through an HTTP proxy, so skip it rather than bypass --proxy.
        if parsed.scheme == "https" and not proxy:
            ssl_info = get_ssl_info(parsed.hostname or "", parsed.port or 443)
            if ssl_info:
                target["ssl_certificate"] = ssl_info

        dns_info = get_dns_records(parsed.hostname or "")
        if dns_info:
            target["dns_records"] = dns_info

        error_page = probe_error_page(base_url, session, probe_timeout)
        if error_page:
            target["error_page"] = error_page

        probed = probe_common_paths(base_url, session, probe_timeout)
        if probed:
            target["probed_paths"] = probed

        # --- #9 .well-known probes ---
        well_known = probe_well_known(base_url, session, probe_timeout)
        if well_known:
            target["well_known"] = well_known

        # --- #8 manifest.json / service-worker ---
        manifest = probe_manifest(base_url, session, probe_timeout)
        if manifest:
            target["manifest"] = manifest
        sw_snippet = probe_service_worker(base_url, session, probe_timeout)
        if sw_snippet:
            target["service_worker_snippet"] = sw_snippet

        # --- #11 OPTIONS allowed methods ---
        allowed_methods = probe_options(base_url, session, probe_timeout)
        if allowed_methods:
            target["allowed_methods"] = allowed_methods

        return target
    finally:
        context.close()


def normalize_tags(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return unique([x.strip() for x in raw.split(",")], limit=30)
    if isinstance(raw, list):
        return unique([str(x) for x in raw], limit=30)
    return [truncate(raw, 100)]


def compact_classification(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    keep = ["cve-id", "cwe-id", "cvss-score", "cpe"]
    result: dict[str, Any] = {}
    for key in keep:
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(value, list):
            result[key] = [truncate(x, 180) for x in value[:10]]
        else:
            result[key] = truncate(value, 300)
    return result


def extract_template_signals(doc: dict[str, Any]) -> tuple[list[str], list[str]]:
    path_hints: list[str] = []
    matcher_words: list[str] = []

    http_entries = doc.get("http")
    if isinstance(http_entries, list):
        for entry in http_entries[:8]:
            if not isinstance(entry, dict):
                continue

            raw_paths = entry.get("path", [])
            if isinstance(raw_paths, str):
                raw_paths = [raw_paths]
            if isinstance(raw_paths, list):
                path_hints.extend(truncate(x, 300) for x in raw_paths[:8])

            raw_requests = entry.get("raw", [])
            if isinstance(raw_requests, str):
                raw_requests = [raw_requests]
            if isinstance(raw_requests, list):
                for req in raw_requests[:5]:
                    first_line = str(req).splitlines()[0] if str(req).splitlines() else ""
                    if first_line:
                        path_hints.append(truncate(first_line, 300))

            matchers = entry.get("matchers", [])
            if isinstance(matchers, list):
                for matcher in matchers[:8]:
                    if not isinstance(matcher, dict):
                        continue
                    words = matcher.get("words", [])
                    if isinstance(words, str):
                        words = [words]
                    if isinstance(words, list):
                        matcher_words.extend(truncate(x, 160) for x in words[:10])

    return unique(path_hints, 20), unique(matcher_words, 25)


def parse_template(path: Path) -> TemplateSummary | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            doc = yaml.safe_load(f)
    except Exception:
        return None

    if not isinstance(doc, dict):
        return None

    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    template_id = truncate(doc.get("id") or path.stem, 200)
    name = truncate(info.get("name") or template_id, 300)
    description = truncate(info.get("description") or "", 700)
    severity = truncate(info.get("severity") or "unknown", 50)
    tags = normalize_tags(info.get("tags"))
    protocols = sorted(k for k in PROTOCOL_KEYS if k in doc)
    classification = compact_classification(info.get("classification"))
    path_hints, matcher_words = extract_template_signals(doc)
    search_text = " ".join(
        [template_id, name, description, *tags, *path_hints, *matcher_words]
    ).lower()

    digest = hashlib.sha1(str(path).encode("utf-8", errors="ignore")).hexdigest()[:12]
    key = f"tpl_{digest}"

    return TemplateSummary(
        key=key,
        template_id=template_id,
        name=name,
        description=description,
        severity=severity,
        tags=tags,
        protocols=protocols,
        classification=classification,
        path_hints=path_hints,
        matcher_words=matcher_words,
        file_path=str(path),
        search_text=search_text,
    )


def load_templates(root: Path, max_templates: int | None = None) -> list[TemplateSummary]:
    files = sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml"))
    if max_templates is not None:
        files = files[:max_templates]

    templates: list[TemplateSummary] = []
    for idx, path in enumerate(files, start=1):
        tpl = parse_template(path)
        if tpl:
            templates.append(tpl)
        if idx % 1000 == 0:
            print(f"[index] scanned {idx}/{len(files)} YAML files...", file=sys.stderr)
    return templates


def connect_template_index(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS templates (
            file_path TEXT PRIMARY KEY,
            mtime_ns INTEGER NOT NULL,
            size INTEGER NOT NULL,
            payload TEXT NOT NULL
        )
        """
    )
    return conn


def ensure_scores(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scores (
            url TEXT NOT NULL,
            model TEXT NOT NULL,
            file_path TEXT NOT NULL,
            template_id TEXT NOT NULL,
            name TEXT NOT NULL,
            score REAL NOT NULL,
            confidence REAL NOT NULL,
            probabilities TEXT NOT NULL,
            severity TEXT NOT NULL,
            tags TEXT NOT NULL,
            PRIMARY KEY (url, model, file_path)
        )
        """
    )


def ensure_profiles(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            url TEXT PRIMARY KEY,
            profile TEXT NOT NULL,
            timestamp REAL NOT NULL
        )
        """
    )


def store_profile(conn: sqlite3.Connection, url: str, profile: dict[str, Any]) -> None:
    ensure_profiles(conn)
    conn.execute(
        """
        INSERT INTO profiles (url, profile, timestamp)
        VALUES (?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET
            profile = excluded.profile,
            timestamp = excluded.timestamp
        """,
        (url, json.dumps(profile, ensure_ascii=False), time.time()),
    )
    conn.commit()


def load_cached_profile(conn: sqlite3.Connection, url: str) -> dict[str, Any] | None:
    ensure_profiles(conn)
    row = conn.execute("SELECT profile FROM profiles WHERE url = ?", (url,)).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def cached_paths(conn: sqlite3.Connection, url: str, model: str) -> set[str]:
    ensure_scores(conn)
    return {
        row[0]
        for row in conn.execute(
            "SELECT file_path FROM scores WHERE url = ? AND model = ?",
            (url, model),
        )
    }


def load_ranked(conn: sqlite3.Connection, url: str, model: str) -> list[RankedTemplate]:
    ensure_scores(conn)
    ranked: list[RankedTemplate] = []
    rows = conn.execute(
        """
        SELECT template_id, name, file_path, score, confidence, probabilities, severity, tags
        FROM scores WHERE url = ? AND model = ?
        """,
        (url, model),
    )
    for template_id, name, file_path, score, confidence, probabilities, severity, tags in rows:
        ranked.append(
            RankedTemplate(
                template_id=template_id,
                name=name,
                file_path=file_path,
                score=float(score),
                confidence=float(confidence),
                probabilities={str(key): float(value) for key, value in json.loads(probabilities).items()},
                severity=severity,
                tags=json.loads(tags),
            )
        )
    return ranked


def store_ranked(conn: sqlite3.Connection, url: str, model: str, ranked: list[RankedTemplate]) -> None:
    if not ranked:
        return
    ensure_scores(conn)
    conn.executemany(
        """
        INSERT INTO scores (
            url, model, file_path, template_id, name, score, confidence, probabilities, severity, tags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url, model, file_path) DO UPDATE SET
            template_id = excluded.template_id,
            name = excluded.name,
            score = excluded.score,
            confidence = excluded.confidence,
            probabilities = excluded.probabilities,
            severity = excluded.severity,
            tags = excluded.tags
        """,
        [
            (
                url,
                model,
                item.file_path,
                item.template_id,
                item.name,
                item.score,
                item.confidence,
                json.dumps(item.probabilities, ensure_ascii=False),
                item.severity,
                json.dumps(item.tags, ensure_ascii=False),
            )
            for item in ranked
        ],
    )
    conn.commit()


def load_templates_cached(
    root: Path,
    db_path: Path,
    max_templates: int | None = None,
    rebuild: bool = False,
) -> list[TemplateSummary]:
    root = root.resolve()
    conn = connect_template_index(db_path)
    try:
        stored_root = conn.execute("SELECT value FROM meta WHERE key = 'templates_root'").fetchone()
        if stored_root is None or stored_root[0] != str(root):
            conn.execute("DELETE FROM templates")
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('templates_root', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(root),),
            )

        files = sorted({path.resolve() for path in root.rglob("*.yaml")} | {path.resolve() for path in root.rglob("*.yml")})
        if rebuild:
            conn.execute("DELETE FROM templates")
        existing = {
            row[0]: (row[1], row[2])
            for row in conn.execute("SELECT file_path, mtime_ns, size FROM templates")
        }
        seen: set[str] = set()
        parsed = 0
        reused = 0
        for idx, path in enumerate(files, start=1):
            stat = path.stat()
            file_key = str(path)
            seen.add(file_key)
            stamp = (stat.st_mtime_ns, stat.st_size)
            if existing.get(file_key) == stamp:
                reused += 1
            else:
                tpl = parse_template(path)
                if tpl is None:
                    conn.execute("DELETE FROM templates WHERE file_path = ?", (file_key,))
                else:
                    conn.execute(
                        """
                        INSERT INTO templates(file_path, mtime_ns, size, payload)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(file_path) DO UPDATE SET
                            mtime_ns = excluded.mtime_ns,
                            size = excluded.size,
                            payload = excluded.payload
                        """,
                        (file_key, stamp[0], stamp[1], json.dumps(asdict(tpl), ensure_ascii=False)),
                    )
                    parsed += 1
            if idx % 1000 == 0:
                conn.commit()
                print(
                    f"[index] scanned {idx}/{len(files)} YAML files, parsed {parsed}, reused {reused}...",
                    file=sys.stderr,
                )

        stale = [file_key for file_key in existing if file_key not in seen]
        if stale:
            conn.executemany("DELETE FROM templates WHERE file_path = ?", [(file_key,) for file_key in stale])
        conn.commit()
        print(
            f"[index] sqlite {db_path}: parsed {parsed}, reused {reused}, removed {len(stale)}",
            file=sys.stderr,
        )

        templates = [
            TemplateSummary(**json.loads(payload))
            for (payload,) in conn.execute("SELECT payload FROM templates ORDER BY file_path")
        ]
    finally:
        conn.close()

    if max_templates is not None:
        return templates[:max_templates]
    return templates


def chunked(items: list[TemplateSummary], size: int) -> list[list[TemplateSummary]]:
    return [items[i : i + size] for i in range(0, len(items), size)]



def candidate_for_state(t: TemplateSummary) -> dict[str, Any]:
    # file_path is deliberately excluded from AI state: it has no semantic value.
    return {
        "id": t.template_id,
        "name": t.name,
        "description": t.description,
        "severity": t.severity,
        "tags": t.tags,
        "protocols": t.protocols,
        "classification": t.classification,
        "path_hints": t.path_hints,
        "matcher_words": t.matcher_words,
    }


def build_payload(target: dict[str, Any], batch: list[TemplateSummary], model: str) -> tuple[dict[str, Any], dict[str, TemplateSummary]]:
    key_map = {t.key: t for t in batch}

    state = {
        "task": "Rank each candidate Nuclei template by relevance to the observed HTTP/HTTPS target. This is relevance triage only; do not infer that a vulnerability exists and do not assume unobserved products/components are present.",
        "relevance_rubric": {
            "0": RELEVANCE_RUBRIC[0],
            "1": RELEVANCE_RUBRIC[1],
            "2": RELEVANCE_RUBRIC[2],
            "3": RELEVANCE_RUBRIC[3],
            "4": RELEVANCE_RUBRIC[4],
        },
        "target": target,
        "candidate_templates": {t.key: candidate_for_state(t) for t in batch},
    }

    questions = {
        t.key: {
            "type": "score",
            "instructions": f"Rate candidate_templates.{t.key} using relevance_rubric.",
            "criteria": RELEVANCE_RUBRIC,
        }
        for t in batch
    }

    return {"state": state, "model": model, "questions": questions}, key_map


def post_jev(
    payload: dict[str, Any],
    api_key: str,
    timeout: float,
    retries: int,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            response = requests.post(
                TYPESAFE_ENDPOINT,
                headers=headers,
                json=payload,
                timeout=timeout,
            )
        except Exception as exc:
            last_error = exc
            if attempt >= retries:
                break
            time.sleep(min(2**attempt, 8))
            continue

        body = response.text[:800]
        if response.status_code == 400:
            if "max_tokens_exceeded" in body:
                raise TokenLimitError(body)
            raise RuntimeError(f"TypeSafe HTTP 400: {body}")
        if response.status_code == 429 or 500 <= response.status_code < 600:
            last_error = RuntimeError(f"TypeSafe temporary error HTTP {response.status_code}: {body}")
            if attempt >= retries:
                break
            time.sleep(min(2**attempt, 8))
            continue
        if response.status_code >= 400:
            raise RuntimeError(f"TypeSafe HTTP {response.status_code}: {body}")
        return response.json()

    raise RuntimeError(f"TypeSafe request failed after retries: {last_error}")


def evaluate_batch(
    batch_index: int,
    total_batches: int,
    target: dict[str, Any],
    batch: list[TemplateSummary],
    model: str,
    api_key: str,
    api_timeout: float,
    retries: int,
    label: str = "",
    timings: bool = False,
    quiet: bool = False,
) -> tuple[list[RankedTemplate], dict[str, int], float]:
    started = time.perf_counter()
    payload, key_map = build_payload(target, batch, model)
    try:
        result = post_jev(payload, api_key, api_timeout, retries)
    except TokenLimitError:
        if len(batch) < 2:
            raise
        midpoint = len(batch) // 2
        print(
            f"[jev] {label} batch {batch_index} exceeded the token limit, "
            f"splitting {len(batch)} into {midpoint}+{len(batch) - midpoint}",
            file=sys.stderr,
        )
        left_ranked, left_usage, _left_seconds = evaluate_batch(
            batch_index,
            total_batches,
            target,
            batch[:midpoint],
            model,
            api_key,
            api_timeout,
            retries,
            label,
            timings,
            quiet,
        )
        right_ranked, right_usage, _right_seconds = evaluate_batch(
            batch_index,
            total_batches,
            target,
            batch[midpoint:],
            model,
            api_key,
            api_timeout,
            retries,
            label,
            timings,
            quiet,
        )
        return (
            left_ranked + right_ranked,
            {
                "input_tokens": left_usage["input_tokens"] + right_usage["input_tokens"],
                "output_tokens": left_usage["output_tokens"] + right_usage["output_tokens"],
            },
            time.perf_counter() - started,
        )

    answers = result.get("answers", {})
    ranked: list[RankedTemplate] = []

    for key, answer in answers.items():
        template = key_map.get(key)
        if template is None or not isinstance(answer, dict):
            continue
        if answer.get("type") != "score":
            continue
        ranked.append(
            RankedTemplate(
                template_id=template.template_id,
                name=template.name,
                file_path=template.file_path,
                score=float(answer.get("score", 0.0)),
                confidence=float(answer.get("confidence", 0.0)),
                probabilities={str(k): float(v) for k, v in answer.get("probabilities", {}).items()},
                severity=template.severity,
                tags=template.tags,
            )
        )

    usage = result.get("usage", {})
    seconds = time.perf_counter() - started
    if not quiet:
        prefix = f"{label} " if label else ""
        timing_suffix = f", {seconds:.2f}s" if timings else ""
        print(
            f"[jev] {prefix}batch {batch_index}/{total_batches}: {len(ranked)} answers, "
            f"input_tokens={usage.get('input_tokens', '?')}{timing_suffix}",
            file=sys.stderr,
        )
    return ranked, {
        "input_tokens": int(usage.get("input_tokens", 0) or 0),
        "output_tokens": int(usage.get("output_tokens", 0) or 0),
    }, seconds


def is_relevant(item: RankedTemplate, min_score: float, min_confidence: float) -> bool:
    return item.score >= min_score and item.confidence >= min_confidence


def print_ranked(results: list[RankedTemplate], min_score: float, min_confidence: float, top: int) -> None:
    ranked = sorted(results, key=lambda item: (item.score, item.confidence), reverse=True)
    high = [item for item in ranked if is_relevant(item, min_score, min_confidence)]

    print()
    print(f"Total templates scored: {len(ranked)}")
    print(
        f"High-priority (score >= {min_score:.2f}, confidence >= {min_confidence:.2f}): {len(high)}"
    )
    print("=" * 110)
    print(f"{'SCORE':>5}  {'CONF':>5}  {'SEVERITY':<10}  {'TEMPLATE ID':<35}  NAME")
    print("-" * 110)
    for item in ranked[:top]:
        print(
            f"{item.score:5.2f}  {item.confidence:5.2f}  "
            f"{item.severity[:10]:<10}  {item.template_id[:35]:<35}  {item.name[:45]}"
        )


def generate_html_report(
    rows: list[dict[str, Any]],
    output_path: Path,
    model: str,
    template_count: int,
    min_score: float = 2.0,
) -> None:
    """Write a self-contained HTML report of the scoring results."""
    from datetime import datetime, timezone

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sections: list[str] = []
    for row in rows:
        url = str(row.get("url") or "")
        error = row.get("error")
        if error:
            sections.append(
                f'<div class="url-section">'
                f'<h2 class="url-title">{_html_escape(url)}</h2>'
                f'<p class="error">Profile error: {_html_escape(str(error))}</p>'
                f'</div>'
            )
            continue

        target = row.get("target") or {}
        techs = target.get("detected_technologies") or []
        all_results = row.get("all_results") or []
        relevant = [r for r in all_results if float(r.get("score", 0)) >= min_score]
        relevant.sort(key=lambda r: float(r.get("score", 0)), reverse=True)
        top_score = max((float(r.get("score", 0)) for r in all_results), default=0.0)

        tech_html = ", ".join(_html_escape(t) for t in techs) if techs else "<em>none detected</em>"

        table_rows: list[str] = []
        for r in relevant:
            tags_str = ", ".join(r.get("tags") or [])
            table_rows.append(
                f"<tr>"
                f"<td>{_html_escape(str(r.get('template_id', '')))}</td>"
                f"<td>{_html_escape(str(r.get('name', '')))}</td>"
                f"<td class=\"score\">{float(r.get('score', 0)):.2f}</td>"
                f"<td>{float(r.get('confidence', 0)):.2f}</td>"
                f"<td>{_html_escape(str(r.get('severity', '')))}</td>"
                f"<td>{_html_escape(tags_str)}</td>"
                f"</tr>"
            )

        table_body = "\n".join(table_rows) if table_rows else '<tr><td colspan="6">No relevant templates</td></tr>'

        sections.append(
            f'<div class="url-section">'
            f'<h2 class="url-title">{_html_escape(url)}</h2>'
            f'<p class="tech">Technologies: {tech_html}</p>'
            f'<div class="summary">'
            f'<span>Total scored: <strong>{len(all_results)}</strong></span>'
            f'<span>Relevant (score &ge; {min_score:.1f}): <strong>{len(relevant)}</strong></span>'
            f'<span>Top score: <strong>{top_score:.2f}</strong></span>'
            f'</div>'
            f'<table>'
            f'<thead><tr>'
            f'<th>Template ID</th><th>Name</th><th>Score</th>'
            f'<th>Confidence</th><th>Severity</th><th>Tags</th>'
            f'</tr></thead>'
            f'<tbody>{table_body}</tbody>'
            f'</table>'
            f'</div>'
        )

    body = "\n".join(sections)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NucleiSniper Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;padding:2rem}}
h1{{color:#58a6ff;font-size:1.8rem;margin-bottom:1.5rem;border-bottom:1px solid #30363d;padding-bottom:.5rem}}
.url-section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin-bottom:1.5rem}}
.url-title{{color:#58a6ff;font-size:1.2rem;margin-bottom:.75rem;word-break:break-all}}
.tech{{color:#8b949e;margin-bottom:.75rem;font-size:.9rem}}
.summary{{display:flex;gap:1.5rem;flex-wrap:wrap;margin-bottom:1rem;font-size:.9rem}}
.summary span{{background:#21262d;padding:.35rem .7rem;border-radius:4px}}
.error{{color:#f85149;font-style:italic}}
table{{width:100%;border-collapse:collapse;font-size:.85rem;margin-top:.5rem}}
th{{text-align:left;background:#21262d;color:#8b949e;padding:.5rem .6rem;border-bottom:2px solid #30363d}}
td{{padding:.45rem .6rem;border-bottom:1px solid #21262d}}
tr:hover{{background:#1c2128}}
td.score{{font-weight:bold;color:#3fb950}}
.footer{{margin-top:2rem;color:#484f58;font-size:.8rem;text-align:center;border-top:1px solid #30363d;padding-top:1rem}}
</style>
</head>
<body>
<h1>NucleiSniper Report</h1>
{body}
<div class="footer">
Model: {_html_escape(model)} &middot; Templates: {template_count} &middot; Generated: {timestamp}
</div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def _html_escape(text: str) -> str:
    """HTML-escape all five significant characters (&, <, >, \", ')."""
    return _html_mod.escape(text, quote=True)


def load_report(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(document, dict) and isinstance(document.get("results"), list):
        return document["results"]
    if isinstance(document, dict) and document.get("target"):
        return [document]
    raise ValueError("Report has neither results[] nor a single target")


def selected_templates(
    row: dict[str, Any],
    min_score: float | None,
    min_confidence: float | None,
    severities: set[str] | None,
) -> list[dict[str, Any]]:
    source = row.get("all_results") or row.get("relevant") or []
    chosen = []
    for item in source:
        score = float(item.get("score", 0.0))
        confidence = float(item.get("confidence", 0.0))
        if min_score is not None and score < min_score:
            continue
        if min_confidence is not None and confidence < min_confidence:
            continue
        if severities and item.get("severity", "").lower() not in severities:
            continue
        if not item.get("file_path"):
            continue
        chosen.append(item)
    chosen.sort(key=lambda item: (float(item.get("score", 0)), float(item.get("confidence", 0))), reverse=True)
    return chosen


def existing_paths(items: list[dict[str, Any]]) -> tuple[list[Path], list[str]]:
    found: list[Path] = []
    missing: list[str] = []
    seen: set[str] = set()
    for item in items:
        raw = str(item["file_path"])
        if raw in seen:
            continue
        seen.add(raw)
        path = Path(raw)
        if path.is_file():
            found.append(path)
        else:
            missing.append(raw)
    return found, missing


def classify_template(path: Path) -> str:
    if path.name.lower() in {"wappalyzer-mapping.yml", "wappalyzer-mapping.yaml"}:
        return "skip"
    folders = {part.lower() for part in path.parts}
    if "workflows" in folders:
        return "workflow"
    if "code" in folders or "file" in folders:
        return "local"
    return "target"


def protocol_flags(paths: list[Path]) -> list[str]:
    flags: list[str] = []
    folders = {part.lower() for path in paths for part in path.parts}
    if "dast" in folders:
        flags.append("-dast")
    if "headless" in folders:
        flags.append("-headless")
    return flags


def nuclei_command(
    nuclei: str,
    url: str,
    template_list: Path | None,
    workflow_list: Path | None,
    jsonl_path: Path,
    rate_limit: int,
    concurrency: int,
    extra_flags: list[str],
) -> list[str]:
    command = [
        nuclei,
        "-u",
        url,
        "-duc",
        #"-stats",
        "-si",
        "5",
        "-rl",
        str(rate_limit),
        "-c",
        str(concurrency),
        "-no-color",
        "-jle",
        str(jsonl_path),
    ]
    if template_list is not None:
        command.extend(["-t", str(template_list)])
    if workflow_list is not None:
        command.extend(["-w", str(workflow_list)])
    command.extend(extra_flags)
    return command


def enrich_findings(jsonl_path: Path, scored_templates: dict[str, dict[str, float | None]]) -> None:
    """Read a Nuclei JSONL findings file and annotate each finding with its Jev relevance score.

    *scored_templates* maps template_id to ``{"score": float, "confidence": float}``.
    If the JSONL file does not exist or is empty, this is a no-op.  Malformed lines are
    preserved unchanged.
    """
    if not jsonl_path.is_file():
        return
    try:
        raw = jsonl_path.read_text(encoding="utf-8")
    except OSError:
        return
    if not raw.strip():
        return

    enriched_lines: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            enriched_lines.append(line)
            continue
        try:
            finding = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            # Malformed line -- keep it as-is
            enriched_lines.append(line)
            continue
        template_id = finding.get("template-id") or finding.get("template_id") or ""
        scores = scored_templates.get(template_id)
        if scores is not None:
            finding["jev_score"] = scores.get("score")
            finding["jev_confidence"] = scores.get("confidence")
        else:
            finding["jev_score"] = None
            finding["jev_confidence"] = None
        enriched_lines.append(json.dumps(finding, ensure_ascii=False))

    jsonl_path.write_text("\n".join(enriched_lines) + "\n", encoding="utf-8")


def nuclei_available(nuclei: str) -> bool:
    if shutil.which(nuclei) is None and not Path(nuclei).is_file():
        print(f"ERROR: nuclei executable not found: {nuclei} (use --nuclei, or --no-scan to score only)", file=sys.stderr)
        return False
    return True


def run_scans(rows: list[dict[str, Any]], args: argparse.Namespace) -> int:
    """Run Nuclei once per report row with templates in score order. Returns the exit code."""
    severities = csv_set(args.severity) or None
    args.scan_dir.mkdir(parents=True, exist_ok=True)
    planned = 0
    failures = 0
    for row in rows:
        url = str(row.get("url") or (row.get("target") or {}).get("final_url") or "")
        if not url:
            print("ERROR: result is missing a URL", file=sys.stderr)
            failures += 1
            continue
        if row.get("error"):
            print(f"[skip] {url} profile error: {row['error']}", file=sys.stderr)
            continue
        # Build scored_templates lookup from all_results for finding enrichment
        all_results = row.get("all_results") or []
        scored_templates: dict[str, dict[str, float | None]] = {}
        for item in all_results:
            tid = item.get("template_id") or ""
            if tid:
                scored_templates[tid] = {
                    "score": item.get("score"),
                    "confidence": item.get("confidence"),
                }

        items = selected_templates(row, args.scan_min_score, args.scan_min_confidence, severities)
        paths, missing = existing_paths(items)
        slug = host_slug(url)
        for gone in missing:
            print(f"[skip] missing template {gone}", file=sys.stderr)
        target_paths = []
        workflow_paths = []
        for path in paths:
            kind = classify_template(path)
            if kind == "target":
                target_paths.append(path)
            elif kind == "workflow":
                workflow_paths.append(path)
            elif kind == "local":
                print(f"[skip] {path.name} does not scan the URL (code/file template)", file=sys.stderr)
            else:
                print(f"[skip] {path.name} is not a Nuclei template", file=sys.stderr)
        if not target_paths and not workflow_paths:
            print(f"[skip] {url} has no URL templates on disk", file=sys.stderr)
            continue

        template_list = None
        workflow_list = None
        if target_paths:
            template_list = args.scan_dir / f"{slug}.templates.txt"
            template_list.write_text("\n".join(str(path) for path in target_paths) + "\n", encoding="utf-8")
        if workflow_paths:
            workflow_list = args.scan_dir / f"{slug}.workflows.txt"
            workflow_list.write_text("\n".join(str(path) for path in workflow_paths) + "\n", encoding="utf-8")
        jsonl_path = args.scan_dir / f"{slug}.jsonl"
        command = nuclei_command(
            args.nuclei,
            url,
            template_list,
            workflow_list,
            jsonl_path,
            args.rate_limit,
            args.concurrency,
            protocol_flags(target_paths),
        )
        planned += 1
        print(
            f"[plan] {url} templates={len(target_paths)} workflows={len(workflow_paths)}",
            file=sys.stderr,
        )
        print(" ".join(command), flush=True)
        if args.dry_run:
            continue
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0:
            print(f"ERROR: nuclei exited {completed.returncode} for {url}", file=sys.stderr)
            failures += 1
        else:
            enrich_findings(jsonl_path, scored_templates)
            print(f"[done] {url} findings={jsonl_path}", file=sys.stderr)

    if planned == 0:
        print("ERROR: nothing to scan", file=sys.stderr)
        return 3
    return 1 if failures else 0


def _run_profile_only(args: argparse.Namespace, urls: list[str]) -> int:
    """Profile every URL and emit JSON without scoring or scanning."""
    try:
        extra_headers = parse_headers(args.header)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    fetch_mode = "playwright" if args.playwright else "requests"
    print(
        f"[profile-only] profiling {len(urls)} url(s) via {fetch_mode}",
        file=sys.stderr,
    )

    if args.playwright:
        results = profile_urls_with_browser(
            urls,
            args.timeout,
            args.insecure,
            args.max_body,
            args.render_wait,
            str(args.playwright_path) if args.playwright_path else None,
            args.proxy,
            extra_headers,
        )
    else:
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.url_workers) as executor:
            futures = {
                executor.submit(
                    profile_url_job,
                    url,
                    args.timeout,
                    args.insecure,
                    args.max_body,
                    None,
                    0.0,
                    None,
                    args.proxy,
                    extra_headers,
                ): url
                for url in urls
            }
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())

    # Build output in URL order
    profile_map: dict[str, tuple[dict[str, Any] | None, str | None]] = {}
    for url, target, error, _seconds in results:
        profile_map[url] = (target, error)

    if len(urls) == 1:
        target, error = profile_map[urls[0]]
        if error:
            print(f"ERROR: Could not profile {urls[0]}: {error}", file=sys.stderr)
            return 3
        output = target
    else:
        profiles = []
        for url in urls:
            target, error = profile_map[url]
            entry: dict[str, Any] = {"url": url}
            if error:
                entry["error"] = error
                print(f"ERROR: Could not profile {url}: {error}", file=sys.stderr)
            else:
                entry["profile"] = target
            profiles.append(entry)
        output = {"profiles": profiles}

    json_text = json.dumps(output, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(json_text, encoding="utf-8")
        print(f"[profile-only] wrote {args.output}", file=sys.stderr)
    else:
        print(json_text)

    return 0


CURRENT_VERSION = "1.0.0"
VERSION_CHECK_URL = "https://mordavid.com/md_versions.yaml"
VERSION_PROJECT_NAME = "NucleiSniper"


def _parse_version(ver: str) -> tuple[int, ...]:
    """Parse '1.2.3' into (1, 2, 3) for comparison. Falls back to (0,) on bad input."""
    try:
        return tuple(int(x) for x in ver.strip().split("."))
    except (ValueError, AttributeError):
        return (0,)


def check_for_updates() -> None:
    """Check mordavid.com for a newer version. Silent on any failure."""
    try:
        resp = requests.get(VERSION_CHECK_URL, timeout=3)
        if resp.status_code != 200:
            return
        data = yaml.safe_load(resp.text)
        if not isinstance(data, dict):
            return
        entry = data.get(VERSION_PROJECT_NAME)
        if not isinstance(entry, dict):
            return
        remote_ver = str(entry.get("version", "")).strip()
        download_url = str(entry.get("url", "")).strip()
        if not remote_ver:
            return
        if _parse_version(remote_ver) > _parse_version(CURRENT_VERSION):
            print(
                f"\033[93m[+] Update available!\n"
                f"    Current version: {CURRENT_VERSION}\n"
                f"    Latest version:  {remote_ver}\n"
                f"    Download: {download_url}\033[0m",
                file=sys.stderr,
            )
    except Exception:
        pass

BANNER = r"""
 _   _            _      _ ____        _                 
| \ | |_   _  ___| | ___(_) ___| _ __ (_)_ __   ___ _ __ 
|  \| | | | |/ __| |/ _ \ \___ \| '_ \| | '_ \ / _ \ '__|
| |\  | |_| | (__| |  __/ |___) | | | | | |_) |  __/ |   
|_| \_|\__,_|\___|_|\___|_|____/|_| |_|_| .__/ \___|_|   
                                        |_|              
"""

BANNER_INFO = (
    "\033[96m\033[1m"
    "🎯 NucleiSniper - AI-Prioritised Nuclei Scanning powered by TypeSafe Jev 🧠\n"
    f"Version {CURRENT_VERSION} | Author: Mor David (www.mordavid.com) | License: PolyForm Strict 1.0.0"
    "\033[0m"
)


def main() -> int:
    print(BANNER, file=sys.stderr)
    print(BANNER_INFO, file=sys.stderr)
    print(file=sys.stderr)
    parser = argparse.ArgumentParser(
        description="Rank Nuclei templates by relevance to HTTP/HTTPS targets with TypeSafe Jev, then run Nuclei with the highest-scoring templates first."
    )
    parser.add_argument("--skip-version-check", action="store_true", help="Skip automatic update check at startup")
    parser.add_argument("urls", nargs="*", help="One or more target URLs, including http:// or https://")
    parser.add_argument(
        "--urls-file",
        type=Path,
        help="Text file with one target URL per line. Blank lines and # comments are ignored.",
    )
    parser.add_argument(
        "--templates",
        "-t",
        type=Path,
        help="Path to the local nuclei-templates directory. Required unless --report is given.",
    )
    parser.add_argument(
        "--index-db",
        type=Path,
        help="SQLite file for the template index. Default: <templates>/.jev_template_index.sqlite. Reused when YAML mtime and size are unchanged.",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"TypeSafe model name (default: {DEFAULT_MODEL})")
    parser.add_argument("--batch-size", type=int, default=50, help="Templates/questions per TypeSafe request (default: 50)")
    parser.add_argument(
        "--url-workers",
        type=int,
        default=4,
        help="Concurrent target-profiling threads (default: 4)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Concurrent TypeSafe requests across all URLs. A URL is sent as soon as it is profiled, while other URLs are still being fetched (default: 3)",
    )
    parser.add_argument("--threshold", type=float, default=2.5, help="Minimum relevance score, 0-4 (default: 2.5)")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Minimum Jev confidence, 0-1 (default: 0). Applied together with --threshold.",
    )
    parser.add_argument("--top", type=int, default=100, help="Maximum matching templates to print per URL (default: 100)")
    parser.add_argument("--max-templates", type=int, default=None, help="POC/debug limit; omit to evaluate all templates")
    parser.add_argument("--severity", help="Comma-separated severities to score and scan, for example medium,high,critical")
    parser.add_argument("--tags", help="Comma-separated tags. A template must include at least one.")
    parser.add_argument("--exclude-tags", help="Comma-separated tags to drop.")
    parser.add_argument("--protocols", help="Comma-separated protocols. A template must use at least one, for example http.")
    parser.add_argument(
        "--profile-only",
        action="store_true",
        help="Profile all target URLs and export the fingerprint as JSON without scoring or scanning. "
        "No TYPESAFE_API_KEY or --templates required. Output goes to -o if set, otherwise stdout.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Profile targets and print the template counts without calling Jev or running Nuclei. "
        "With --report: print the Nuclei commands without running them.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Reuse scores already stored in the index database for the same URL and model.",
    )
    parser.add_argument("--proxy", help="Proxy URL for target fetches, for example http://127.0.0.1:8080")
    parser.add_argument("--header", action="append", default=[], help="Extra target header, 'Name: Value'. Repeatable.")
    parser.add_argument("--rebuild-index", action="store_true", help="Reparse every YAML file into the SQLite index.")
    parser.add_argument("--output-dir", type=Path, help="Write one JSON report per URL into this directory.")
    parser.add_argument("--timeout", type=float, default=15.0, help="Target HTTP timeout seconds (default: 15)")
    parser.add_argument("--api-timeout", type=float, default=120.0, help="TypeSafe API timeout seconds (default: 120)")
    parser.add_argument("--retries", type=int, default=2, help="Retries for temporary TypeSafe failures (default: 2)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification for the targets")
    parser.add_argument(
        "--playwright",
        action="store_true",
        help="Render each target in headless Chromium before profiling. Use this for SPAs.",
    )
    parser.add_argument(
        "--playwright-path",
        type=Path,
        help="Chromium executable for --playwright. Default: the browser installed by Playwright.",
    )
    parser.add_argument(
        "--render-wait",
        type=float,
        default=2.0,
        help="Seconds to wait after DOMContentLoaded so client-rendered content can appear (default: 2, used with --playwright)",
    )
    parser.add_argument("--max-body", type=int, default=1_000_000, help="Max target response bytes to inspect (default: 1,000,000)")
    parser.add_argument("--output", "-o", type=Path, help="Write the JSON report for every URL to this file")
    parser.add_argument(
        "--dump-first-payload",
        type=Path,
        help="Write the first TypeSafe request payload to a JSON file for Playground inspection",
    )
    parser.add_argument(
        "--timings",
        action="store_true",
        help="Print and save elapsed seconds for indexing, profiling, and each Jev batch.",
    )
    parser.add_argument(
        "--cache-profile",
        action="store_true",
        help="Cache target profiles in the SQLite index DB and reuse them on subsequent runs.",
    )
    parser.add_argument(
        "--refresh-profile",
        action="store_true",
        help="Force re-profiling even when --cache-profile has a cached profile.",
    )

    scan = parser.add_argument_group("scan", "Run Nuclei with templates ordered by Jev score. Every scored template runs unless a --scan-* filter or --severity drops it.")
    scan.add_argument("--no-scan", action="store_true", help="Score only; do not run Nuclei.")
    scan.add_argument("--no-prefilter", action="store_true", help="Disable the tag-based prefilter that reduces templates before Jev scoring.")
    scan.add_argument(
        "--html-report",
        type=Path,
        default=None,
        help="Generate a self-contained HTML report from the scoring results.",
    )
    scan.add_argument("--report", type=Path, help="Skip scoring and scan from an existing relevance.json (written with -o or --output-dir).")
    scan.add_argument("--nuclei", default="nuclei", help="Nuclei executable (default: nuclei)")
    scan.add_argument("--scan-dir", type=Path, default=Path("nuclei-runs"), help="Directory for template lists and JSONL findings (default: nuclei-runs)")
    scan.add_argument("--rate-limit", type=int, default=150, help="Nuclei -rl, requests per second (default: 150)")
    scan.add_argument("--concurrency", type=int, default=25, help="Nuclei -c, templates in parallel (default: 25)")
    scan.add_argument("--scan-min-score", type=float, default=2.0, help="Skip templates below this Jev score (default: 2.0). Pass 0 to run all.")
    scan.add_argument("--scan-min-confidence", type=float, default=None, help="Skip templates below this Jev confidence (default: run all)")
    args = parser.parse_args()

    if not args.skip_version_check:
        check_for_updates()

    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    if args.url_workers < 1:
        parser.error("--url-workers must be >= 1")
    if args.render_wait < 0:
        parser.error("--render-wait must be >= 0")
    if args.playwright_path is not None and not args.playwright_path.is_file():
        parser.error(f"Playwright browser executable does not exist: {args.playwright_path}")
    if args.playwright:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError:
            print(
                "ERROR: --playwright needs the playwright package and Chromium. "
                "pip install playwright && playwright install chromium",
                file=sys.stderr,
            )
            return 2
    if not (0.0 <= args.threshold <= 4.0):
        parser.error("--threshold must be between 0 and 4")
    if not (0.0 <= args.min_confidence <= 1.0):
        parser.error("--min-confidence must be between 0 and 1")
    if args.rate_limit < 1:
        parser.error("--rate-limit must be >= 1")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")

    if args.report is not None:
        if args.urls or args.urls_file:
            parser.error("--report scans an existing report; do not pass target URLs with it")
        if args.no_scan:
            parser.error("--report with --no-scan has nothing to do")
        if not args.report.is_file():
            parser.error(f"Report does not exist: {args.report}")
        if not args.dry_run and not nuclei_available(args.nuclei):
            return 2
        try:
            rows = load_report(args.report)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"ERROR: Could not read report: {exc}", file=sys.stderr)
            return 2
        if args.html_report is not None:
            # Try to recover template_count from the report metadata
            try:
                report_meta = json.loads(args.report.read_text(encoding="utf-8-sig"))
                report_template_count = int(report_meta.get("template_count", 0)) if isinstance(report_meta, dict) else 0
            except Exception:
                report_template_count = 0
            generate_html_report(rows, args.html_report, args.model, report_template_count, min_score=args.scan_min_score)
            print(f"[output] wrote HTML report {args.html_report}", file=sys.stderr)
        return run_scans(rows, args)

    if args.templates is None and not args.profile_only:
        parser.error("--templates is required unless --report or --profile-only is given")
    if args.templates is not None and (not args.templates.exists() or not args.templates.is_dir()):
        parser.error(f"Template directory does not exist: {args.templates}")
    if args.templates is not None and args.index_db is None:
        args.index_db = args.templates.resolve() / ".jev_template_index.sqlite"
    if args.urls_file is not None and not args.urls_file.is_file():
        parser.error(f"URLs file does not exist: {args.urls_file}")

    try:
        urls = collect_urls(args.urls, args.urls_file)
    except ValueError as exc:
        parser.error(str(exc))
    except OSError as exc:
        parser.error(f"Could not read URLs file: {exc}")

    if args.profile_only:
        return _run_profile_only(args, urls)

    api_key = os.getenv("TYPESAFE_API_KEY")
    if not api_key and not args.dry_run:
        print("ERROR: Set TYPESAFE_API_KEY in your environment.", file=sys.stderr)
        return 2
    try:
        extra_headers = parse_headers(args.header)
    except ValueError as exc:
        parser.error(str(exc))

    # --dry-run skips Jev, so there are no scores to scan with.
    scanning = not args.no_scan and not args.dry_run
    # Fail before spending API credit on a run whose scan step cannot start.
    if scanning and not nuclei_available(args.nuclei):
        return 2

    code, rows = score_targets(args, urls, api_key, extra_headers)
    if code != 0 or not scanning:
        return code
    print(file=sys.stderr)
    return run_scans(rows, args)


def score_targets(
    args: argparse.Namespace,
    urls: list[str],
    api_key: str | None,
    extra_headers: dict[str, str],
) -> tuple[int, list[dict[str, Any]]]:
    """Profile every URL and score all templates with Jev. Returns (exit code, report rows)."""
    severity_filter = csv_set(args.severity)
    tag_filter = csv_set(args.tags)
    exclude_tag_filter = csv_set(args.exclude_tags)
    protocol_filter = csv_set(args.protocols)

    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    fetch_mode = "playwright" if args.playwright else "requests"
    run_started = time.perf_counter()
    print(
        f"[target] profiling {len(urls)} url(s) with {args.url_workers} threads via {fetch_mode}",
        file=sys.stderr,
    )
    print(f"[index] loading templates from {args.templates}", file=sys.stderr)

    runs_by_url: dict[str, dict[str, Any]] = {}
    templates_box: dict[str, Any] = {"templates": None, "index_seconds": 0.0, "ready": False}
    jev_futures: dict[concurrent.futures.Future, tuple[dict[str, Any], int, str]] = {}
    state_lock = threading.Lock()
    dumped_payload = False
    jev_started_at: float | None = None
    jev_executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
    score_conn = connect_template_index(args.index_db) if args.resume else None
    if score_conn is not None:
        ensure_scores(score_conn)
    profile_conn = connect_template_index(args.index_db) if args.cache_profile else None
    if profile_conn is not None:
        ensure_profiles(profile_conn)

    def submit_run(run: dict[str, Any]) -> None:
        nonlocal dumped_payload, jev_started_at
        found = templates_box["templates"]
        if found is None or run["target"] is None or run.get("queued"):
            return
        run["queued"] = True
        selected = list(found)
        selected = apply_template_filters(
            selected,
            severity_filter,
            tag_filter,
            exclude_tag_filter,
            protocol_filter,
        )
        selected = prefilter_templates(selected, run["target"], args.no_prefilter)
        resumed = 0
        if args.resume and score_conn is not None:
            known = cached_paths(score_conn, run["url"], args.model)
            resumed = sum(1 for template in selected if template.file_path in known)
            selected = [template for template in selected if template.file_path not in known]
            if args.cache_profile and selected:
                print(f"[jev] {len(selected)} new templates to score for {run['url']}", file=sys.stderr)
        run["candidate_count"] = len(selected)
        run["resumed_count"] = resumed
        batches = chunked(selected, args.batch_size)
        run["batch_count"] = len(batches)
        label = urlparse(run["url"]).netloc
        if args.dry_run:
            print(
                f"[dry-run] {label} {len(selected)}/{len(found)} templates, "
                f"{len(batches)} batches, resumed {resumed}",
                file=sys.stderr,
            )
            return
        if not batches:
            if resumed:
                print(
                    f"[jev] {label} {resumed} templates already scored, nothing new to send",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[jev] {label} no relevant templates ({len(selected)}/{len(found)}), skipped",
                    file=sys.stderr,
                )
            return
        if jev_started_at is None:
            jev_started_at = time.perf_counter()
        if args.dump_first_payload and not dumped_payload:
            earlier_pending = False
            for earlier_url in urls:
                if earlier_url == run["url"]:
                    break
                earlier = runs_by_url.get(earlier_url)
                if earlier is None or earlier["target"] is not None:
                    earlier_pending = True
                    break
            if not earlier_pending:
                payload, _ = build_payload(run["target"], batches[0], args.model)
                args.dump_first_payload.write_text(
                    json.dumps(payload, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                dumped_payload = True
                print(f"[debug] wrote first payload to {args.dump_first_payload}", file=sys.stderr)
        print(
            f"[jev] queued {label} ({len(batches)} batches, {len(selected)}/{len(found)} templates)",
            file=sys.stderr,
        )
        for idx, batch in enumerate(batches, start=1):
            future = jev_executor.submit(
                evaluate_batch,
                idx,
                len(batches),
                run["target"],
                batch,
                args.model,
                api_key,
                args.api_timeout,
                args.retries,
                label,
                args.timings,
                _tqdm is not None,
            )
            jev_futures[future] = (run, idx, label)

    def publish_templates(found: list[TemplateSummary], index_seconds_value: float) -> None:
        templates_box["templates"] = found
        templates_box["index_seconds"] = index_seconds_value
        templates_box["ready"] = True
        for queued in runs_by_url.values():
            submit_run(queued)

    def record_profile(url: str, target: dict[str, Any] | None, error: str | None, seconds: float) -> None:
        timing_suffix = f" profile={seconds:.2f}s" if args.timings else ""
        with state_lock:
            runs_by_url[url] = {
                "url": url,
                "target": target,
                "error": error,
                "results": [],
                "usage": {"input_tokens": 0, "output_tokens": 0},
                "batch_count": 0,
                "failed_batches": 0,
                "profile_seconds": round(seconds, 3),
                "jev_seconds": 0.0,
                "queued": False,
                "candidate_count": 0,
                "resumed_count": 0,
            }
            if index_future.done() and not templates_box["ready"]:
                found, index_seconds_value = index_future.result()
                publish_templates(found, index_seconds_value)
            elif templates_box["ready"]:
                submit_run(runs_by_url[url])
        if error:
            print(f"ERROR: Could not profile {url}: {error}{timing_suffix}", file=sys.stderr)
            return
        print(
            f"[target] status={target['status_code']} final_url={target['final_url']} "
            f"fetch={target.get('fetch', fetch_mode)} tech={target['detected_technologies']}{timing_suffix}",
            file=sys.stderr,
        )

    def load_templates_timed() -> tuple[list[TemplateSummary], float]:
        started = time.perf_counter()
        found = load_templates_cached(args.templates, args.index_db, args.max_templates, args.rebuild_index)
        return found, time.perf_counter() - started

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as index_executor:
        index_future = index_executor.submit(load_templates_timed)
        profile_wall_started = time.perf_counter()
        urls_to_profile = list(urls)
        if profile_conn is not None and not args.refresh_profile:
            cached_urls: set[str] = set()
            for url in urls_to_profile:
                cached = load_cached_profile(profile_conn, url)
                if cached is not None:
                    print(f"[target] using cached profile for {url}", file=sys.stderr)
                    record_profile(url, cached, None, 0.0)
                    cached_urls.add(url)
            if cached_urls:
                urls_to_profile = [u for u in urls_to_profile if u not in cached_urls]

        if not urls_to_profile:
            pass
        elif args.playwright:
            buckets = round_robin(urls_to_profile, args.url_workers)
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(buckets)) as executor:
                bucket_futures = {
                    executor.submit(
                        profile_urls_with_browser,
                        bucket,
                        args.timeout,
                        args.insecure,
                        args.max_body,
                        args.render_wait,
                        str(args.playwright_path) if args.playwright_path else None,
                        args.proxy,
                        extra_headers,
                    ): bucket
                    for bucket in buckets
                }
                for future in concurrent.futures.as_completed(bucket_futures):
                    bucket = bucket_futures[future]
                    try:
                        rows = future.result()
                    except Exception as exc:
                        rows = [(url, None, str(exc), 0.0) for url in bucket]
                    for url, target, error, seconds in rows:
                        record_profile(url, target, error, seconds)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.url_workers) as executor:
                profile_futures = {
                    executor.submit(
                        profile_url_job,
                        url,
                        args.timeout,
                        args.insecure,
                        args.max_body,
                        None,
                        0.0,
                        None,
                        args.proxy,
                        extra_headers,
                    ): url
                    for url in urls_to_profile
                }
                for future in concurrent.futures.as_completed(profile_futures):
                    url, target, error, seconds = future.result()
                    record_profile(url, target, error, seconds)
        if profile_conn is not None:
            for url in urls_to_profile:
                run = runs_by_url.get(url)
                if run and run.get("target") is not None:
                    store_profile(profile_conn, url, run["target"])
        profile_wall_seconds = time.perf_counter() - profile_wall_started
        with state_lock:
            if not templates_box["ready"]:
                found, index_seconds_value = index_future.result()
                publish_templates(found, index_seconds_value)

    templates = templates_box["templates"] or []
    index_seconds = float(templates_box["index_seconds"])
    if not templates:
        print("ERROR: No readable Nuclei YAML templates found.", file=sys.stderr)
        jev_executor.shutdown(wait=False, cancel_futures=True)
        if score_conn is not None:
            score_conn.close()
        if profile_conn is not None:
            profile_conn.close()
        return 4, []
    index_suffix = f" in {index_seconds:.2f}s" if args.timings else ""
    print(f"[index] loaded {len(templates)} templates{index_suffix}", file=sys.stderr)

    runs = [runs_by_url[url] for url in urls]
    if score_conn is not None:
        for run in runs:
            if run["error"]:
                continue
            cached = load_ranked(score_conn, run["url"], args.model)
            have = {item.file_path for item in run["results"]}
            run["results"].extend(item for item in cached if item.file_path not in have)
    jev_wall_seconds = 0.0
    try:
        completed_iter: Any = concurrent.futures.as_completed(jev_futures)
        progress_bar = None
        if _tqdm is not None and jev_futures:
            progress_bar = _tqdm(
                completed_iter,
                total=len(jev_futures),
                desc="Jev scoring",
                unit="batch",
                file=sys.stderr,
            )
            completed_iter = progress_bar
        try:
            for future in completed_iter:
                run, idx, label = jev_futures[future]
                if progress_bar is not None:
                    progress_bar.set_postfix_str(label, refresh=True)
                try:
                    ranked, usage, seconds = future.result()
                except Exception as exc:
                    run["failed_batches"] += 1
                    print(f"ERROR: {label} batch {idx} failed: {exc}", file=sys.stderr)
                    continue
                run["results"].extend(ranked)
                run["usage"]["input_tokens"] += usage["input_tokens"]
                run["usage"]["output_tokens"] += usage["output_tokens"]
                run["jev_seconds"] = round(run["jev_seconds"] + seconds, 3)
                if score_conn is not None:
                    store_ranked(score_conn, run["url"], args.model, ranked)
        finally:
            if progress_bar is not None:
                progress_bar.close()
        if jev_started_at is not None:
            jev_wall_seconds = time.perf_counter() - jev_started_at
    finally:
        jev_executor.shutdown(wait=True)

    total_usage = {"input_tokens": 0, "output_tokens": 0}
    profiled_ok = 0
    for run in runs:
        total_usage["input_tokens"] += run["usage"]["input_tokens"]
        total_usage["output_tokens"] += run["usage"]["output_tokens"]
        print()
        print("=" * 110)
        print(f"URL: {run['url']}")
        if run["error"]:
            print(f"PROFILE ERROR: {run['error']}")
            continue
        profiled_ok += 1
        run["results"].sort(key=lambda item: (item.score, item.confidence), reverse=True)
        print_ranked(run["results"], args.threshold, args.min_confidence, args.top)
        if run["failed_batches"]:
            print(
                f"[jev] {urlparse(run['url']).netloc} failed batches: "
                f"{run['failed_batches']}/{run['batch_count']}",
                file=sys.stderr,
            )

    evaluated = sum(len(run["results"]) for run in runs)
    print(
        f"\nURLs: {len(runs)} profiled_ok={profiled_ok} profile_failed={len(runs) - profiled_ok} | "
        f"Evaluated answers: {evaluated} | templates: {len(templates)} | "
        f"TypeSafe input tokens: {total_usage['input_tokens']} | "
        f"output tokens: {total_usage['output_tokens']}",
        file=sys.stderr,
    )

    total_seconds = time.perf_counter() - run_started
    timings = {
        "total_seconds": round(total_seconds, 3),
        "index_seconds": round(index_seconds, 3),
        "profile_wall_seconds": round(profile_wall_seconds, 3),
        "jev_wall_seconds": round(jev_wall_seconds, 3),
    }
    if args.timings:
        print(
            f"[time] total={timings['total_seconds']:.2f}s "
            f"index={timings['index_seconds']:.2f}s "
            f"profile_wall={timings['profile_wall_seconds']:.2f}s "
            f"jev_wall={timings['jev_wall_seconds']:.2f}s",
            file=sys.stderr,
        )
        for run in runs:
            print(
                f"[time] {run['url']} profile={run['profile_seconds']:.2f}s jev={run['jev_seconds']:.2f}s",
                file=sys.stderr,
            )

    rows = [
        {
            "url": run["url"],
            "error": run["error"],
            "target": run["target"],
            "evaluated_count": len(run["results"]),
            "failed_batches": run["failed_batches"],
            "batch_count": run["batch_count"],
            "candidate_count": run["candidate_count"],
            "resumed_count": run.get("resumed_count", 0),
            "usage": run["usage"],
            "relevant": [
                asdict(item)
                for item in run["results"]
                if is_relevant(item, args.threshold, args.min_confidence)
            ],
            "all_results": [asdict(item) for item in run["results"]],
        }
        for run in runs
    ]
    if args.timings:
        for row, run in zip(rows, runs):
            row["profile_seconds"] = run["profile_seconds"]
            row["jev_seconds"] = run["jev_seconds"]

    if args.output:
        report = {
            "model": args.model,
            "rubric": RELEVANCE_RUBRIC,
            "threshold": args.threshold,
            "min_confidence": args.min_confidence,
            "template_count": len(templates),
            "url_count": len(runs),
            "usage": total_usage,
            "results": rows,
        }
        if args.timings:
            report["timings"] = timings
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[output] wrote {args.output}", file=sys.stderr)

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for row in rows:
            per_url = {
                "model": args.model,
                "rubric": RELEVANCE_RUBRIC,
                "threshold": args.threshold,
                "min_confidence": args.min_confidence,
                "template_count": len(templates),
                **row,
            }
            destination = args.output_dir / report_filename(row["url"])
            destination.write_text(json.dumps(per_url, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[output] wrote {destination}", file=sys.stderr)

    if getattr(args, "html_report", None) is not None:
        generate_html_report(rows, args.html_report, args.model, len(templates), min_score=args.scan_min_score)
        print(f"[output] wrote HTML report {args.html_report}", file=sys.stderr)

    if score_conn is not None:
        score_conn.close()
    if profile_conn is not None:
        profile_conn.close()

    if profiled_ok == 0:
        return 3, rows
    return 0, rows

if __name__ == "__main__":
    raise SystemExit(main())
