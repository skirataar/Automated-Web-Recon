# Overview — Automated Web Recon & Attack Surface Mapper

> **Scope**: Detection and fingerprinting only.  No exploitation.  Authorised targets only.

---

## What this tool does

The **Recon Mapper** automates the reconnaissance phase of a web security assessment.  Given a target domain, it progressively discovers, enriches, and correlates the following:

- **Host inventory** — all domains, sub-domains, and IPs related to the target
- **Open services** — TCP/UDP ports and service banners
- **Technology stack** — web servers, frameworks, languages, CDNs, WAFs
- **Attack surface** — HTTP endpoints, API routes, forms, JavaScript entrypoints
- **Vulnerability indicators** — service versions mapped to CVEs, security-header gaps, cookie misconfigurations, permissive CORS

Output is stored in a local SQLite database and rendered into JSON, Markdown, or HTML reports for the assessor.

---

## Four-Phase Pipeline

All data flows through four sequential phases.  Each phase reads the current asset list from storage, runs its registered modules, and writes new assets and findings back to storage before the next phase begins.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           Recon Mapper Pipeline                               │
│                                                                              │
│  INPUT: target domain (e.g. example.com)                                     │
│                                                                              │
│  ┌───────────┐   assets    ┌───────────┐   assets    ┌───────────┐  assets  │
│  │ 1.passive │ ──────────▶ │ 2.active  │ ──────────▶ │ 3.surface │ ───────▶ │
│  └───────────┘             └───────────┘             └───────────┘          │
│        │                         │                         │                 │
│        ▼                         ▼                         ▼                 │
│   [storage]               [storage]               [storage]                  │
│                                                                              │
│                                                 ┌──────────────────┐        │
│                                                 │ 4.vuln_indicators│        │
│                                                 └──────────────────┘        │
│                                                          │                   │
│                                                          ▼                   │
│                                                     [storage]                │
│                                                          │                   │
│                                                          ▼                   │
│                                               OUTPUT: report (JSON/MD/HTML)  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 1 — Passive Reconnaissance

**Goal**: Build the initial asset inventory without sending any traffic to the target.

All data is sourced from public third-party services.

| Module (planned) | Data collected |
|---|---|
| `dns_enum` | A, MX, TXT, NS, CNAME, SOA records |
| `cert_ct` | Sub-domains via Certificate Transparency (crt.sh / Censys) |
| `whois_lookup` | Registrar, registration dates, nameservers |
| `shodan_lookup` | Passive port data, banners, tags (API key required) |
| `github_dork` | Exposed endpoints, API keys, config files in public repos |

**Risk**: None — only public data sources are queried.

---

### Phase 2 — Active Reconnaissance

**Goal**: Enrich the passive asset inventory with live host data.

⚠️ This phase sends packets to the target.  Written authorisation **required**.

| Module (planned) | Data collected |
|---|---|
| `port_scan` | Open TCP/UDP ports (asyncio-based, rate-limited) |
| `banner_grab` | Service banners and version strings |
| `http_probe` | HTTP/HTTPS status codes, redirect chains, server headers |
| `waf_detect` | WAF/CDN fingerprinting heuristics |
| `tls_audit` | TLS protocol versions, cipher suites, certificate details |

**Risk**: Low (non-exploitative, non-destructive).  May trigger IDS/WAF alerts.

---

### Phase 3 — Surface Mapping

**Goal**: Enumerate the target's exposed functionality and entry points.

⚠️ This phase interacts with the target's web application.  Written authorisation **required**.

| Module (planned) | Data collected |
|---|---|
| `endpoint_crawler` | URLs, forms, links (depth-limited spider) |
| `js_analyzer` | Endpoints, API paths, and potential secrets in JS bundles |
| `api_discovery` | REST, GraphQL, and gRPC surface hints |
| `dir_brute` | Known directories and files via wordlist probing |
| `param_miner` | Hidden HTTP parameters via reflection analysis |

**Risk**: Moderate (generates crawl traffic; may trigger rate-limiting or WAF blocks).

---

### Phase 4 — Vulnerability Indicators

**Goal**: Map collected fingerprints to known weakness indicators.

⚠️ This phase reads active findings from storage and may make targeted follow-up requests.  Written authorisation **required**.  **No exploitation is performed.**

| Module (planned) | Data collected |
|---|---|
| `version_cve` | CVE IDs from service versions via NVD / OSV feeds |
| `header_audit` | Missing / misconfigured HTTP security headers (HSTS, CSP …) |
| `cookie_audit` | Cookie Secure / HttpOnly / SameSite attribute gaps |
| `cors_check` | Permissive `Access-Control-Allow-Origin` policies |
| `default_creds` | Login page fingerprints matching known default-credential services |

**Risk**: Low (largely analytical); targeted HTTP requests are observational only.

---

## Scope Statement

This tool is designed exclusively for **legal, authorised security assessments**.

| ✅ Permitted | ❌ Not permitted |
|---|---|
| Passive OSINT from public sources | Exploiting discovered vulnerabilities |
| Non-destructive network probing | Modifying any data on target systems |
| Technology stack fingerprinting | Denial-of-service or flood activity |
| Vulnerability indicator correlation | Running against targets without written permission |
| Structured reporting of findings | Sharing findings with unauthorised parties |

**You are solely responsible for ensuring you have explicit, written permission from the asset owner before running any non-passive phase.**

> Unauthorised use of this tool against systems you do not own or have permission to test may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, the EU NIS2 Directive, or equivalent legislation in your jurisdiction.

---

## Next Steps

- See [`passive-recon.md`](passive-recon.md) for passive module implementation details.
- See [`active-recon.md`](active-recon.md) for active module implementation details.
- See [`surface-mapping.md`](surface-mapping.md) for surface-mapping module details.
- See [`vuln-indicators.md`](vuln-indicators.md) for vulnerability indicator details.
- See [`glossary.md`](glossary.md) for term definitions.
