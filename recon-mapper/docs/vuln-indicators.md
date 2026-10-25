# Vulnerability Indicators

> **Risk level**: Low — largely analytical; targeted follow-up requests are observational only.
> ⚠️ Written authorisation from the asset owner is **required** before running this phase.
>
> **This phase performs detection and reporting ONLY.  No vulnerability is exploited.**

---

## Purpose

The vuln-indicators phase correlates everything discovered in Phases 1–3 against known weakness databases and security best-practice baselines to surface actionable findings for the assessor.

Output findings in this phase have the richest context and the highest signal-to-noise ratio of the entire pipeline.

---

## Planned Modules

| Module file | Function | Data source |
|---|---|---|
| `modules/vuln_indicators/version_cve.py` | Service version → CVE mapping | NVD API, OSV.dev |
| `modules/vuln_indicators/header_audit.py` | HTTP security header analysis | OWASP header baseline |
| `modules/vuln_indicators/cookie_audit.py` | Cookie attribute gap analysis | RFC 6265 / OWASP |
| `modules/vuln_indicators/cors_check.py` | Permissive CORS detection | HTTP probe |
| `modules/vuln_indicators/default_creds.py` | Default credential page hints | Fingerprint database |

---

## Module Interface Contract

```python
def run(assets: list[Asset], storage: ReconStorage, target: str) -> None:
    """Analyse collected data and persist indicator findings."""
    ...
```

- Read assets and their associated findings from storage.
- Create new `Finding` objects with appropriate severity, category, and evidence.
- **Never** send authentication attempts, payloads, or exploit code.

---

## Severity Guidelines

| Indicator | Severity |
|---|---|
| Critical CVE (CVSS ≥ 9.0) on exposed service | `HIGH` |
| Missing HSTS, CSP, or X-Frame-Options | `MEDIUM` |
| Missing `HttpOnly` or `Secure` cookie flags | `MEDIUM` |
| TLS 1.0 / 1.1 in use | `MEDIUM` |
| Wildcard CORS (`Access-Control-Allow-Origin: *`) | `MEDIUM` |
| High CVE (CVSS 7.0–8.9) | `MEDIUM` |
| Information disclosure in headers | `LOW` |
| Moderate CVE (CVSS 4.0–6.9) | `LOW` |
| Version disclosure (Server, X-Powered-By) | `INFO` |
| CVE with no public exploit | `INFO` |

---

## Version → CVE Mapping (`version_cve`)

TODO: Implement `modules/vuln_indicators/version_cve.py`.

```python
# TODO: For each asset, parse tech_stack entries for version strings
# TODO: Query NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
#       or OSV (https://api.osv.dev/v1/query) for matching CVEs
# TODO: Create Finding per CVE with severity mapped from CVSS base score
# TODO: Cache NVD responses locally to avoid rate limits
```

---

## HTTP Header Audit (`header_audit`)

TODO: Implement `modules/vuln_indicators/header_audit.py`.

```python
# REQUIRED_HEADERS = {
#     "Strict-Transport-Security": Severity.MEDIUM,
#     "Content-Security-Policy":   Severity.MEDIUM,
#     "X-Frame-Options":           Severity.MEDIUM,
#     "X-Content-Type-Options":    Severity.LOW,
#     "Referrer-Policy":           Severity.LOW,
#     "Permissions-Policy":        Severity.LOW,
# }
# TODO: For each Finding with category="http-response", parse headers
# TODO: Create a Finding for each missing required header
```

---

## Cookie Audit (`cookie_audit`)

TODO: Implement `modules/vuln_indicators/cookie_audit.py`.

```python
# TODO: Parse Set-Cookie headers from stored http-response findings
# TODO: Flag cookies missing Secure, HttpOnly, or SameSite attributes
# TODO: Flag session cookies without __Host- prefix on HTTPS targets
```

---

## CORS Check (`cors_check`)

TODO: Implement `modules/vuln_indicators/cors_check.py`.

```python
# TODO: For API endpoints discovered in Phase 3, send a preflight request
#       with Origin: https://attacker.example and check ACAO response header
# TODO: Wildcard or reflected origin → MEDIUM finding
```

---

## References

- [NVD REST API](https://nvd.nist.gov/developers/vulnerabilities)
- [OSV.dev API](https://google.github.io/osv.dev/api/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [RFC 6265 — HTTP State Management](https://datatracker.ietf.org/doc/html/rfc6265)
