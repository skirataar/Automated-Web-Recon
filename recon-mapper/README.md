# Recon Mapper

> **Automated Web Reconnaissance & Attack Surface Mapping**
> Detection and fingerprinting only — no exploitation, authorised targets only.

---

## What is this?

Recon Mapper is a modular, phase-driven Python tool that automates the recon phase of a security assessment against **explicitly authorised targets**.  It collects and correlates information about a target's internet-facing attack surface — domains, IPs, open services, technology stack, endpoints, and potential vulnerability indicators — and produces structured reports for the assessor.

It does **not** exploit any vulnerability.  Every interaction is bounded by an explicit scope statement (see below).

---

## Quick Start

```bash
# 1. Clone / enter the project
cd recon-mapper

# 2. Create a virtual environment
python -m venv .venv && source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Passive-only run (safe, no direct target traffic)
python main.py --target example.com --phases passive

# 5. Full pipeline with scope confirmation prompt
python main.py --target example.com --scope-confirm --output ./reports/

# 6. Help
python main.py --help
```

---

## Four-Phase Pipeline

```
┌────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────────┐
│  1. passive │───▶│  2. active   │───▶│  3. surface │───▶│ 4. vuln_indicators│
└────────────┘    └──────────────┘    └─────────────┘    └──────────────────┘
  OSINT / DNS      Port scan /           Endpoint /          CVE correlation /
  CT logs /        banner grab /         JS analysis /       header audit /
  WHOIS            HTTP probe            API discovery        cookie audit
```

### Phase 1 — Passive

No packets are sent to the target. Data is gathered exclusively from public third-party sources:

- DNS record enumeration (A, MX, TXT, NS, CNAME, SOA)
- Certificate Transparency log scraping (crt.sh, Censys)
- WHOIS / RDAP registration data
- Shodan passive host data (optional, API key required)
- GitHub code-search dorking for target-related artefacts

### Phase 2 — Active

⚠️ **Requires written authorisation.** Direct, non-exploitative interaction with the target:

- TCP/UDP port scanning
- Service banner capture for version fingerprinting
- HTTP/HTTPS probing, redirect chains, status codes
- Web Application Firewall detection heuristics
- TLS version, cipher-suite, and certificate analysis

### Phase 3 — Surface

⚠️ **Requires written authorisation.** Enumerate the target's exposed functionality:

- Web content spidering to collect URLs and forms
- JavaScript bundle analysis for extracted endpoints and keys
- REST / GraphQL / gRPC API surface detection
- Directory and file brute-force (wordlist-driven)
- Hidden HTTP parameter discovery

### Phase 4 — Vuln Indicators

⚠️ **Requires written authorisation.** Map findings to known issues — **detection only**:

- Service version → CVE correlation via NVD / OSV
- HTTP security header analysis (HSTS, CSP, X-Frame-Options …)
- Cookie attribute checks (Secure, HttpOnly, SameSite)
- Permissive CORS policy detection
- Default credential hints on login pages

---

## Project Structure

```
recon-mapper/
├── core/               # Shared models, storage, and pipeline orchestrator
│   ├── models.py       # Asset, Finding dataclasses; Severity enum
│   ├── storage.py      # SQLite-backed persistence layer
│   └── orchestrator.py # Phase-aware Pipeline with decorator registration
├── modules/
│   ├── passive/        # OSINT, DNS, CT log modules
│   ├── active/         # Port scan, banner grab, HTTP probe modules
│   ├── surface/        # Crawler, JS analyser, API discovery modules
│   └── vuln_indicators/# CVE mapping, header/cookie audit modules
├── reports/
│   └── report_generator.py  # JSON / Markdown / HTML report writer
├── tests/              # pytest test suite
├── docs/               # Design documentation
├── main.py             # CLI entrypoint (argparse → Pipeline)
└── requirements.txt    # Python dependencies
```

---

## Scope Statement

| ✅ In scope | ❌ Out of scope |
|---|---|
| Passive OSINT (DNS, CT, WHOIS) | Exploiting any vulnerability |
| Non-destructive port scanning | Modifying data on target systems |
| HTTP probing & banner grabbing | Denial-of-service activity |
| Technology stack fingerprinting | Credential stuffing / brute-force authentication |
| CVE / misconfiguration mapping | Running against targets without written permission |

**Only run this tool against targets for which you hold explicit, written authorisation.**  Unauthorised use may violate computer-fraud laws in your jurisdiction.

---

## CLI Reference

```
python main.py [OPTIONS]

Required:
  --target DOMAIN         Primary target domain or IP (e.g. example.com)

Output:
  --output DIR            Report output directory [default: ./reports/]
  --db FILE               SQLite database file    [default: recon.db]

Pipeline:
  --phases PHASE [...]    Phases to run: passive active surface vuln_indicators
                          [default: all four phases]
  --scope-confirm         Interactively prompt before gated phases

Logging:
  --log-level LEVEL       DEBUG | INFO | WARNING | ERROR [default: INFO]
```

---

## Licence

MIT — see `LICENSE` (to be added).  Use responsibly.
