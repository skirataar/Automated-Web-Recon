# Glossary

Terms used throughout the Recon Mapper documentation and codebase.

---

## A

**Asset**
: A discovered host or service within the target scope.  Represented by the
`core.models.Asset` dataclass.  Identified by a stable UUID (`asset_id`) and
characterised by `domain`, `ip`, `ports`, `tech_stack`, `discovered_via`, and
`first_seen`.

**Attack Surface**
: The total set of entry points through which an attacker could attempt to gain
unauthorised access to a system — open ports, HTTP endpoints, APIs, web forms,
etc.  Enumerated primarily in Phase 3 (surface mapping).

---

## B

**Banner Grabbing**
: Connecting to an open TCP port and reading the initial response bytes to
identify the service name and version.  A passive-flavoured active technique.

---

## C

**Certificate Transparency (CT)**
: An open framework for monitoring and auditing digital certificates.  CT logs
record every TLS certificate issued by a CA, making them a rich passive source
of sub-domain names.

**CORS (Cross-Origin Resource Sharing)**
: An HTTP mechanism that controls how web pages can request resources from
domains other than the one that served the page.  Misconfigured CORS policies
can leak sensitive data to attacker-controlled origins.

**CVE (Common Vulnerabilities and Exposures)**
: A public catalogue of known security vulnerabilities.  Each entry has a
unique identifier (e.g. `CVE-2023-1234`) and a CVSS base score.

**CVSS (Common Vulnerability Scoring System)**
: A numerical scale (0.0–10.0) representing the severity of a vulnerability.
Used in this tool to map CVE scores to `Severity` enum values.

---

## D

**Discovery (Discovered Via)**
: The `discovered_via` field on an `Asset` records the name of the module that
first added the asset to storage — e.g. `"dns_enum"`, `"cert_ct"`.

**DNS Enumeration**
: Querying DNS servers to collect all records associated with a target domain
(`A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, `SOA`).

---

## F

**Finding**
: A single security-relevant observation tied to an Asset.  Represented by
`core.models.Finding`.  Every finding has a `category`, `severity`, `description`,
and raw `evidence` string.

**Fingerprinting**
: Identifying the software, version, or configuration of a remote service
without exploiting it — e.g. reading `Server: nginx/1.24.0` from an HTTP header.

---

## G

**Gate (Scope Gate)**
: The interactive confirmation prompt displayed before gated pipeline phases
(active, surface, vuln_indicators).  Enabled with `--scope-confirm`.  Ensures
the operator explicitly acknowledges authorisation before sending traffic to
the target.

---

## O

**OSINT (Open-Source Intelligence)**
: Intelligence gathered from publicly available sources — CT logs, WHOIS
records, DNS, Shodan, GitHub, etc.  The basis of Phase 1 (passive).

---

## P

**Phase**
: One of the four ordered pipeline stages: `passive`, `active`, `surface`,
`vuln_indicators`.  Each phase reads from and writes to the shared storage.

**Pipeline**
: The `core.orchestrator.Pipeline` class that drives phase execution, enforces
ordering, and manages the scope gate.

---

## R

**RDAP (Registration Data Access Protocol)**
: A modern replacement for WHOIS that returns structured JSON instead of plain
text.  Used to retrieve domain registration, registrar, and nameserver data.

---

## S

**Severity**
: Criticality level of a `Finding`: `INFO` < `LOW` < `MEDIUM` < `HIGH`.
Defined in `core.models.Severity`.

**Scope**
: The set of systems the assessor is authorised to test.  The tool enforces
explicit scope acknowledgement via the `--scope-confirm` gate.

**Sub-domain Enumeration**
: Discovering all sub-domains of a target domain via DNS queries, CT logs,
brute-force, or passive sources.

---

## T

**Tech Stack**
: The list of technology identifiers detected for an `Asset` — e.g.
`["nginx/1.24", "PHP/8.2", "WordPress/6.5"]`.  Populated progressively
across multiple phases.

**TLS Audit**
: Inspection of a host's TLS configuration: protocol version (TLS 1.0/1.1/1.2/1.3),
cipher suites, certificate validity, and Subject Alt Names.

---

## V

**Vulnerability Indicator**
: A data point that *suggests* a vulnerability may be present — e.g. a service
version matching a CVE, or a missing security header.  Indicators are not
confirmed exploits; they require manual validation.

---

## W

**WAF (Web Application Firewall)**
: A network appliance or cloud service that inspects HTTP traffic and blocks
malicious requests.  WAF presence may affect the accuracy of active probing.

**WHOIS**
: A legacy protocol for querying domain registration information.  Being
superseded by RDAP but still widely available.
