"""
modules.vuln_indicators
=======================
Vulnerability indicator modules (fingerprint-to-CVE mapping, misconfiguration
detection — detection and reporting ONLY, no exploitation).

⚠️  Always obtain written authorization before running these modules.

Planned modules (TODO – implement individually):
  - version_cve     : Map service versions to known CVEs via NVD / OSV
  - header_audit    : HTTP security header analysis (HSTS, CSP, X-Frame …)
  - cookie_audit    : Cookie attribute checks (Secure, HttpOnly, SameSite)
  - cors_check      : Detect permissive CORS policies
  - default_creds   : Detect login pages with known default credential hints
"""
