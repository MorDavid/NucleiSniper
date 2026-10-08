<div align="center">

# 🎯 NucleiSniper — AI-Prioritised Nuclei Scanning

<img src="logo.png" alt="NucleiSniper Logo" width="500">

![NucleiSniper Banner](https://img.shields.io/badge/NucleiSniper-v1.0.0-red?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![Nuclei](https://img.shields.io/badge/Nuclei-Templates-orange?style=for-the-badge)
![TypeSafe Jev](https://img.shields.io/badge/TypeSafe-Jev%20AI-purple?style=for-the-badge)

**Run every Nuclei template — highest-relevance first — powered by TypeSafe Jev AI scoring.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [How Scoring Works](#-how-scoring-works) • [Configuration](#%EF%B8%8F-configuration-options) • [Disclaimer](#%EF%B8%8F-legal-disclaimer)

</div>

---

## 🎯 About

NucleiSniper is a single-script pipeline that uses **TypeSafe Jev AI** to rank all Nuclei templates by relevance to each target, then runs Nuclei with the most-relevant templates first.

### 🧠 AI-Powered Scoring Pipeline
- **Stage 1 (Profile & Score)**: Deep-fingerprint each target, then send template batches to Jev AI for relevance scoring (0–4)
- **Stage 2 (Execute)**: Run Nuclei with all templates ordered by score — critical findings surface first

### 🚀 Why NucleiSniper?

Running `nuclei -u target.com` fires **13,764+ templates in arbitrary order**. WordPress plugin checks run against a Django app. Industrial controller probes hit a blog. You wait for thousands of irrelevant checks before the ones that matter even start.

NucleiSniper solves this — every template still runs, but **high-value checks execute first** so you get actionable findings faster.

| Vanilla Nuclei | NucleiSniper |
|---|---|
| Templates run in directory order | Templates run **highest-relevance first** |
| No target awareness | Deep target profiling with 30+ signal types |
| Same scan for every target | Each target gets a **custom-ranked template list** |
| Findings trickle in randomly | **Critical findings surface early** |
| Single run, no resume | **Interruptible** — `--resume` picks up where you left off |

---

## ✨ Features

### 🧠 **AI-Powered Prioritisation**
- Scores every Nuclei template (0–4) against each target using TypeSafe Jev
- Templates sorted by relevance score — critical checks run first
- Auto-splits oversized batches when Jev's token limit is exceeded
- Prioritisation, not filtering — every template still runs

### 🔍 **Deep Target Profiling**
- ~100 technology fingerprints (WordPress, React, Spring, nginx, etc.)
- HTML comments, inline script snippets, stylesheet & iframe URLs
- Asset version strings extracted from JS/CSS filenames (e.g. `jquery/3.7.1`)
- Full redirect chain with status codes
- Cookie attributes (Secure, HttpOnly, SameSite, persistent flags)
- HTTP response time measurement
- Favicon hash (Shodan-compatible mmh3)
- robots.txt / sitemap.xml parsing
- TLS certificate details (CN, issuer, SANs, validity)
- DNS records (A/AAAA/CNAME)
- 404 error page fingerprinting
- 27+ common path probes (`/.git/HEAD`, `/.env`, `/graphql`, …)
- `.well-known` endpoint probes (`security.txt`, `openid-configuration`, etc.)
- `manifest.json` / service-worker detection
- OPTIONS allowed methods discovery

### ⚡ **Concurrent Pipeline**
- `--url-workers` profile multiple targets in parallel
- `--workers` send Jev scoring batches concurrently
- Overlapping: Jev scoring starts as soon as a target's profile completes
- Template YAML → SQLite index (saves ~70s on 13K+ templates)

### 🌐 **SPA Support**
- `--playwright` renders targets in headless Chromium before profiling
- Anti-bot-detection: UA spoofing and webdriver override
- JS globals detection: React, Vue, Next.js, Angular, Svelte, jQuery, etc.

### 🔀 **Flexible Workflow**
- Default: score + scan in one go
- `--no-scan`: score only, save report for later
- `--report`: scan from an existing report without re-scoring
- `--resume`: reuse stored scores from SQLite
- `--dry-run`: preview without spending API credit or running Nuclei
- `--html-report`: generate a self-contained visual report

### 🛡️ **Fail-Safe Design**
- If `nuclei` isn't on PATH, stops *before* calling Jev (no wasted API credit)
- TLS verification always disabled — works against self-signed, mismatched, or expired certs
- Automatic retry with exponential backoff on Jev API errors

---

## 🔧 Installation

### Prerequisites
```bash
# Python 3.10 or higher
python --version
```

- **Nuclei** installed and on PATH ([install guide](https://docs.projectdiscovery.io/tools/nuclei/install))
- **Nuclei templates** cloned locally (`nuclei -update-templates`)
- **TypeSafe API key** — set as `TYPESAFE_API_KEY` environment variable

### Set Up a Virtual Environment (recommended)
```bash
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate it
#   Windows (PowerShell):
.venv\Scripts\Activate.ps1
#   macOS / Linux:
source .venv/bin/activate
```

> **Note:** The `python -m venv .venv` step is only needed once. In every new terminal session, re-run the activation command before using the tool.

### Install Dependencies
```bash
git clone https://github.com/YourUser/NucleiSniper.git
cd NucleiSniper

pip install -r requirements.txt
```

**Required packages:**
- `requests` — HTTP client
- `PyYAML` — YAML template parsing
- `beautifulsoup4` — HTML analysis
- `tqdm` — Progress bar for Jev scoring

### Optional: Playwright (for SPAs)
```bash
pip install playwright
playwright install chromium
```

---

## 📖 Usage

### Command Structure
```bash
python NucleiSniper.py <URLs> [options]
```

NucleiSniper runs both stages in one command: **score**, then **scan**. Add `--no-scan` to stop after scoring, or pass `--report relevance.json` to scan from an earlier report without scoring again.

---

### 📝 Stage 1: Score & Rank

```bash
python NucleiSniper.py <URLs> -t <templates-dir> -o relevance.json --no-scan
```

**What it does:**

1. **Index templates** — Walk `nuclei-templates/**/*.yaml`, parse metadata, cache in SQLite. Only re-parses changed files.

2. **Profile targets** — Fetch each URL, extract 30+ signal types (headers, tech fingerprints, HTML comments, inline scripts, asset versions, TLS cert, DNS, cookies, redirect chain, common paths, `.well-known` endpoints, manifest, OPTIONS methods, and more).

3. **Prefilter** — Drop templates that can't match (code/file templates, unmatched product tags). Keeps ~8.6% of 13,764 templates with 100% recall.

4. **Score with Jev** — Batch ~50 templates per API call. Returns score (0–4), confidence (0–1), and probability distribution per template. Auto-splits on token limit.

5. **Write output** — `relevance.json` with all scored templates, target profile, and usage stats.

---

### 🚀 Stage 2: Execute Nuclei

```bash
python NucleiSniper.py --report relevance.json --scan-dir nuclei-runs
```

**What it does:**

1. Sort all templates by score descending (confidence as tiebreaker)
2. Classify: `target` → `-t`, `workflow` → `-w`, `code`/`file` → skip
3. Write sorted template lists per host
4. Run Nuclei with `-duc -stats -si 5` and your rate limits
5. Findings written to `<host>.jsonl` (JSON Lines)

---

## 🎯 Examples

### 1. Basic Scan — Single Target
```powershell
$env:TYPESAFE_API_KEY = "your-api-key"

python NucleiSniper.py http://target.com `
    -t ~/nuclei-templates `
    -o relevance.json
```

### 2. Multiple Targets from File
```powershell
python NucleiSniper.py `
    --urls-file urls.txt `
    -t ~/nuclei-templates `
    --url-workers 4 --workers 5 `
    --rate-limit 100 `
    -o relevance.json
```

### 3. SPA Target with Playwright
```powershell
python NucleiSniper.py https://spa-app.example.com `
    -t ~/nuclei-templates `
    --playwright --render-wait 3 `
    -o relevance.json
```

### 4. Resume Interrupted Scoring
```powershell
python NucleiSniper.py http://target.com `
    -t ~/nuclei-templates `
    --resume -o relevance.json
```

### 5. Re-scan Existing Report (Critical/High Only)
```powershell
python NucleiSniper.py --report relevance.json --severity critical,high
```

### 6. Dry-Run — Preview Without API Calls
```powershell
# Profile targets and count templates; no Jev calls, no scan
python NucleiSniper.py http://target.com -t ./nuclei-templates --dry-run

# Print Nuclei commands from an existing report
python NucleiSniper.py --report relevance.json --dry-run
```

### 7. Generate HTML Report
```powershell
python NucleiSniper.py http://target.com `
    -t ~/nuclei-templates `
    --html-report report.html --no-scan
```

---

## 🧠 How Scoring Works

### What Gets Sent to Jev

For each batch of ~50 templates, the script builds a payload containing:
- **Target profile** — All 30+ signal types from the profiling stage
- **Template metadata** — id, name, description, severity, tags, protocols, path hints, matcher words
- **Relevance rubric** — the 0–4 scale below

### The Relevance Rubric

| Score | Meaning |
|-------|---------|
| **0** | **Not relevant** — no evidence the target relates to what this template checks |
| **1** | **Weak** — only generic or indirect evidence; poorly supported |
| **2** | **Plausible** — some matching technology/endpoint/behavior, but important evidence is missing |
| **3** | **Relevant** — good evidence the template applies to this product/component/protocol |
| **4** | **Highly relevant** — direct, strong evidence closely matching the specific product/version/endpoint |

### What Jev Returns

For each template:
- **`probabilities`** — distribution across the 5 scores, e.g. `{0: 0.00, 1: 0.03, 2: 0.03, 3: 0.18, 4: 0.76}`
- **`score`** — expected value (weighted average): `0×0.00 + 1×0.03 + 2×0.03 + 3×0.18 + 4×0.76 = 3.66`
- **`confidence`** — how concentrated the distribution is (0–1)

### Example

`apache-detect.yaml` scored against a bWAPP target running Apache:

```json
{
  "score": 3.66,
  "confidence": 0.71,
  "probabilities": {"0": 0.0, "1": 0.03, "2": 0.03, "3": 0.18, "4": 0.76}
}
```

76% probability of "highly relevant" → score 3.66. Makes sense — the server *is* Apache.

Meanwhile, `niagara-fox-info-enum.yaml` (industrial controller) scores near 0 — no evidence of that on the target.

### Benchmark Results

Measured against a real run on `itsecgames.com` (13,764 templates, `jev-latest`):

| Metric | Value |
|---|---|
| Score distribution | <1: 98.6%, ≥2: 0.3%, ≥3: 0.03% |
| Non-determinism (same payload twice) | MAE 0.043 |
| Batch dependence (scored alone vs. in batch of 50) | MAE 0.273 |
| Prefilter recall (score ≥3) | 4/4 (100%) |
| Prefilter token saving | 6.19M → ~495K input tokens (−91%) |

> **Note:** Ordering is best-effort. Nuclei runs `-c` templates concurrently, so execution is roughly — not strictly — score-ordered. Use `--scan-min-score` or `--severity` when you need a hard cut.

---

## ⚙️ Configuration Options

### Scoring Options
| Parameter | Description | Default |
|-----------|-------------|---------|
| `urls` | One or more target URLs | — |
| `--urls-file` | Text file with target URLs (one per line) | — |
| `-t`, `--templates` | Path to nuclei-templates directory | required unless `--report` |
| `--index-db` | SQLite file for the template index and `--resume` scores | `<templates>/.jev_template_index.sqlite` |
| `--model` | TypeSafe Jev model name | `jev-latest` |
| `--batch-size` | Templates per Jev API request | `50` |
| `--url-workers` | Concurrent target-profiling threads | `4` |
| `--workers` | Concurrent Jev scoring threads | `3` |
| `--threshold` | Relevance score threshold for summary display | `2.5` |
| `--min-confidence` | Minimum confidence for summary display | `0.0` |
| `--top` | Max templates to print in summary table | `100` |
| `--max-templates` | Debug limit on templates to evaluate | all |
| `-o`, `--output` | Output JSON file for all URLs | — |
| `--output-dir` | One JSON per URL in this directory | — |
| `--resume` | Reuse stored scores from SQLite | off |
| `--rebuild-index` | Force reparse all YAML files | off |
| `--dry-run` | Profile only; no Jev calls, no scan | off |

### Filter Options
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--severity` | Comma-separated severities (e.g. `medium,high,critical`) | all |
| `--tags` | Template must include at least one of these tags | all |
| `--exclude-tags` | Drop templates with any of these tags | none |
| `--protocols` | Template must use one of these protocols (e.g. `http`) | all |

### Network & Rendering Options
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--proxy` | Proxy URL for target fetches | — |
| `--header` | Extra header (`Name: Value`), repeatable | — |
| `--timeout` | Target HTTP timeout (seconds) | `15` |
| `--api-timeout` | Jev API timeout (seconds) | `120` |
| `--retries` | Retries for temporary Jev failures | `2` |
| `--insecure` | Disable TLS verification for targets (always off by default) | off |
| `--playwright` | Render targets in headless Chromium | off |
| `--playwright-path` | Custom Chromium executable path | auto |
| `--render-wait` | Seconds to wait after DOM load (Playwright) | `2.0` |
| `--max-body` | Max response bytes to inspect | `1,000,000` |

### Scan Options
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--no-scan` | Score only; do not run Nuclei | off |
| `--no-prefilter` | Disable the tag-based prefilter | off |
| `--html-report` | Generate a self-contained HTML report | — |
| `--report` | Skip scoring and scan from an existing `relevance.json` | — |
| `--nuclei` | Nuclei executable path | `nuclei` |
| `--scan-dir` | Directory for findings and template lists | `nuclei-runs` |
| `--rate-limit` | Nuclei requests per second (`-rl`) | `150` |
| `--concurrency` | Nuclei parallel templates (`-c`) | `25` |
| `--scan-min-score` | Skip templates below this score | `2.0` |
| `--scan-min-confidence` | Skip templates below this confidence | run all |

### Debug Options
| Parameter | Description | Default |
|-----------|-------------|---------|
| `--dump-first-payload` | Save first Jev request payload to file | — |
| `--timings` | Print and save elapsed time per phase | off |
| `--skip-version-check` | Skip automatic update check at startup | off |

---

## 📁 Output Structure

```
nuclei-runs/
├── target.com.templates.txt     # Template list sorted by Jev score
├── target.com.workflows.txt     # Workflow templates
└── target.com.jsonl             # Nuclei findings (JSON Lines)
```

Generated artifacts (`relevance.json`, `nuclei-runs/`, `*.sqlite`) are git-ignored. Reports contain absolute template paths from the machine that scored them, so re-run scoring locally rather than sharing reports between machines.

---

## ⚠️ Legal Disclaimer

**FOR AUTHORISED SECURITY TESTING ONLY**

This tool is designed for:
- ✅ Scanning systems you own or have written permission to test
- ✅ Educational and research use in controlled environments
- ✅ Bug bounty programs with explicit scope

**DO NOT USE FOR:**
- ❌ Scanning systems without authorisation
- ❌ Using findings for malicious purposes
- ❌ Violating any applicable laws or regulations

**The authors assume no liability for misuse of this tool.**

---

## 👨‍💻 About the Author

**Mor David** — Offensive Security Specialist & AI Security Researcher

I specialize in **offensive security** with a focus on integrating **Artificial Intelligence** and **Large Language Models (LLM)** into penetration testing workflows. My expertise combines traditional red team techniques with cutting-edge AI technologies to develop next-generation security tools.

### 🔗 Connect with Me
- **LinkedIn**: [linkedin.com/in/mor-david-cyber](https://linkedin.com/in/mor-david-cyber)
- **Website**: [www.mordavid.com](https://www.mordavid.com)

### 🛡️ RootSec Community
Join our cybersecurity community for the latest in offensive security, AI integration, and advanced penetration testing techniques:

**🔗 [t.me/root_sec](https://t.me/root_sec)**

RootSec is a community of security professionals, researchers, and enthusiasts sharing knowledge about:
- Advanced penetration testing techniques
- AI-powered security tools
- Red team methodologies
- Security research and development
- Industry insights and discussions

---

<div align="center">

**⭐ Star this repository if NucleiSniper helped you find bugs faster! ⭐**

**Made with ❤️ by [Mor David](https://www.mordavid.com) | Join [RootSec Community](https://t.me/root_sec) | Powered by [TypeSafe Jev AI](https://typesafe.ai)**

</div>
