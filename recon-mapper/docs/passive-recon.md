# Passive Reconnaissance

> **Risk level**: None — no traffic is sent to the target.
> All data is sourced from public third-party services.

---

## Purpose

The passive phase builds the initial asset inventory using open-source intelligence (OSINT).
Because no packets are sent directly to the target, this phase can be run safely without
written authorisation (though authorisation is always recommended before any assessment).

---

## Modules

| Module file | Status | Function | Data source |
|---|---|---|---|
| `modules/passive/subdomain_enum.py` | ✅ **Implemented** | CT log + passive-DNS subdomain enumeration | crt.sh (primary), HackerTarget (fallback) |
| `modules/passive/whois_dns.py` | ✅ **Implemented** | DNS record enumeration + WHOIS data | dnspython (all record types), python-whois |
| `modules/passive/shodan_lookup.py` | 🔲 TODO | Passive host data | Shodan API (key required) |
| `modules/passive/github_dork.py` | 🔲 TODO | Public code exposure | GitHub Search API |

---

## Module Interface Contract

Every passive module must expose a `run` function with this signature:

```python
def run(assets: list[Asset], storage: ReconStorage, target: str) -> None:
    """Discover sub-domains / IPs and persist them via storage.save_asset()."""
    ...
```

- **Read** existing `assets` to avoid re-querying known hosts.
- **Write** new `Asset` objects via `storage.save_asset()`.
- **Write** `Finding` objects if passive data reveals a notable observation
  (e.g. leaked credentials in a public repo).
- Must not raise unhandled exceptions — log and continue on per-record errors.

---

## DNS Enumeration (`dns_enum`)

TODO: Implement `modules/passive/dns_enum.py`.

Planned record types: `A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, `SOA`.

```python
# TODO: Use dnspython resolver
# TODO: For each record type, create/update an Asset with domain and ip fields
# TODO: Call storage.save_asset() for each discovered host
```

---

## Subdomain Enumeration via CT Logs — `subdomain_enum` ✅

**File**: [`modules/passive/subdomain_enum.py`](../modules/passive/subdomain_enum.py)

### Why CT logs leak subdomains

The TLS PKI mandates (RFC 9162 / Chrome CT Policy) that every certificate issued
by a trusted CA is submitted to at least two publicly-readable, append-only
Certificate Transparency logs *before* browsers will trust it.  The certificate's
**Subject Alternative Name (SAN)** field lists every hostname the cert protects,
and those names are written verbatim into the log — permanently and world-readably.

Consequences for recon:

- **No DNS required** — a subdomain appears in CT even with no DNS record.
- **Wildcards are informative** — `*.internal.example.com` reveals structure.
- **Pre-certificate (PRECERT) entries** are logged too, so revoked certs still leave a trace.
- **Historical record** — certificates from years ago map old infrastructure.

```
  CA issues cert for: staging.example.com, dev-api.example.com
             │
             ▼  (RFC 9162 mandate)
   CT Log (append-only, Merkle tree, public)
             │
             ▼
   crt.sh aggregates → JSON API → recon-mapper
```

### Primary source — crt.sh

crt.sh (Sectigo) aggregates every major CT log shard (Google Argon, Cloudflare
Nimbus, DigiCert, Let's Encrypt Oak, …) in near-real time.

```
GET https://crt.sh/?q=%.example.com&output=json
```

Each JSON record contains a `name_value` field — a newline-separated list of SANs.
A single cert covering many domains yields multiple subdomains per record.

### Fallback source — HackerTarget passive-DNS

If crt.sh returns HTTP 429 or is unreachable, the module automatically falls back
to HackerTarget's passive-DNS hostsearch:

```
GET https://api.hackertarget.com/hostsearch/?q=example.com
```

Response format: plain-text `hostname,ip` pairs.  Free tier supports ~100 queries/day
without authentication.  HackerTarget sources from independent DNS sensors and crawl
data, making it **complementary** (not a duplicate) to CT logs.

### Normalisation pipeline

All candidate hostnames go through a strict normalisation pipeline before
being persisted:

```
Raw SAN / passive-DNS entry
      │
      ├─ strip whitespace & lowercase
      ├─ remove wildcard prefix (*. → "")
      ├─ reject bare IP addresses
      ├─ reject empty strings
      ├─ validate with RFC 1123 hostname regex
      ├─ check in-scope (must be ≡ target or subdomain of target)
      └─ deduplicate against existing storage assets
             │
             ▼
         Asset object → storage.save_asset()
```

### Pipeline registration

Register in `main.py` (uncomment the TODO block):

```python
from modules.passive.subdomain_enum import run as subdomain_enum_run
pipeline.register("passive", subdomain_enum_run)
```

Or using the decorator:

```python
@pipeline.module("passive")
async def subdomain_enum_wrapper(assets, storage, target):
    from modules.passive.subdomain_enum import run
    await run(assets, storage, target)
```

### Output

| Output type | Content |
|---|---|
| `Asset` per new subdomain | `domain=<subdomain>`, `discovered_via="cert_ct/crt.sh"` (or fallback label) |
| One `Finding` on root asset | `category="subdomain-enum"`, `severity=INFO`, full hostname list as evidence |

### Limitations & known edge cases

| Edge case | Behaviour |
|---|---|
| crt.sh rate-limit (HTTP 429) | Automatic fallback to HackerTarget |
| crt.sh network failure | Treated as rate-limit; fallback activates |
| HackerTarget free-tier exhausted | Logs warning; zero results from fallback |
| Wildcard certs (`*.example.com`) | Wildcard stripped; root domain retained |
| Multi-level wildcards (`*.*.example.com`) | Collapsed to root; further subdomain-specific certs needed |
| Subdomains from *other* orgs sharing a cert | Scope filter (`_is_in_scope`) discards them |

---

## WHOIS Lookup (`whois_lookup`)

TODO: Implement `modules/passive/whois_lookup.py`.

```python
# TODO: Use python-whois or rdap to retrieve registration details
# TODO: Store registrar, creation date, nameservers as Finding evidence
```

---

## DNS Record Enumeration + WHOIS — `whois_dns` ✅

**File**: [`modules/passive/whois_dns.py`](../modules/passive/whois_dns.py)

### What each record type reveals

| Record | Resolves to | Intelligence value |
|---|---|---|
| `A` | IPv4 address | Hosting provider (AWS/GCP/Azure/CDN vs origin), IP-range attribution |
| `AAAA` | IPv6 address | Dual-stack status; IPv6 often bypasses IPv4-only WAF rules |
| `MX` | Mail server + priority | Email provider (Google Workspace, M365, Proofpoint, Mimecast, SendGrid…) |
| `TXT` | Arbitrary text | **SPF** (authorised mail senders), **DKIM** keys, **verification tokens** (SaaS vendor disclosure), **DMARC** policy |
| `NS` | Authoritative nameservers | DNS provider (Route 53, Cloudflare, NS1…); prerequisite for zone-transfer attempts |
| `CNAME` | Alias target hostname | Third-party hosting; dangling CNAMEs → **subdomain takeover** candidates |
| `SOA` | Primary NS, hostmaster, serial, TTLs | Update cadence, hostmaster email (often redacted), zone staleness |

### TXT record vendor disclosure

TXT records are the highest-signal passive record type.  This module classifies
every TXT value against a pattern library covering **20+ vendor tokens**:

```
v=spf1 include:_spf.google.com include:sendgrid.net ~all
                     ↑                    ↑
               Google Workspace       SendGrid
               mail confirmed         mail confirmed
```

Each `include:` clause in an SPF record is extracted individually and tagged
in `asset.tech_stack` as `mail-sender:<domain>` — building a vendor graph
without any active probing.

Verification tokens (e.g. `atlassian-domain-verification=abc123`) confirm the
org has linked a specific SaaS product to their domain, regardless of whether
it's externally visible otherwise.

### DMARC policy detection

The `_dmarc.<domain>` TXT record reveals email security posture:

| DMARC policy | Meaning | Finding description |
|---|---|---|
| `p=none` | Monitoring only | ⚠️ Not enforced — spoofed emails reach inboxes |
| `p=quarantine` | Spam-folder suspicious mail | Partially enforced |
| `p=reject` | Drop unauthenticated mail | Fully enforced |

### CNAME subdomain takeover detection

When a CNAME points to a service provider's hostname (e.g. `shop.example.com
→ example.myshopify.com`) and that account is later deleted, the CNAME becomes
*dangling* and another user can claim the service endpoint, effectively hijacking
the subdomain.  The module checks 20 known takeover-prone services and emits
a `LOW`-severity Finding for each candidate:

> GitHub Pages, AWS S3, Azure Web Apps, Heroku, Netlify, Vercel,
> Shopify, Zendesk, Statuspage, ReadMe, Ghost, Surge.sh, Webflow,
> Unbounce, Freshdesk, Intercom, HelpScout, and more.

### WHOIS — surviving fields post-GDPR

| Field | Reliably present? | Notes |
|---|---|---|
| Registrar | ✅ Yes | Who manages the domain |
| Creation date | ✅ Yes | Domain age; very young = higher risk |
| Expiry date | ✅ Yes | Upcoming expiry = possible hijack vector |
| Updated date | ✅ Yes | Last modification timestamp |
| Nameservers | ✅ Yes | Registry authoritative view |
| Registrant org | ⚠️ Sometimes | Redacted for privacy proxy registrations |
| Registrant country | ⚠️ Sometimes | Jurisdiction info |
| Registrant name/email/phone | ❌ Redacted | GDPR/ICANN Temporary Specification |
| DNSSEC status | ✅ Yes | Whether the zone is signed |

### Pipeline registration

```python
from modules.passive.whois_dns import run as whois_dns_run
pipeline.register("passive", whois_dns_run)
```

> **Ordering matters**: register `subdomain_enum` first so that `whois_dns`
> receives the full subdomain list and can query DNS for every discovered host.

### Output

| Finding category | Severity | Content |
|---|---|---|
| `dns/a` `dns/aaaa` `dns/mx` etc. | `INFO` | All values for that record type |
| `txt/spf` | `INFO` | SPF record + extracted `include:` mail senders |
| `txt/dmarc` | `INFO` | DMARC policy with enforcement note |
| `txt/dkim` | `INFO` | DKIM public key (truncated to 400 chars) |
| `txt/vendor-token` | `INFO` | Named SaaS verification token |
| `dns/cname-takeover-candidate` | `LOW` | Dangling CNAME to known takeover-prone service |
| `whois` | `INFO` | Registrar, dates, nameservers, DNSSEC status |

### Limitations & known edge cases

| Edge case | Behaviour |
|---|---|
| NXDOMAIN / record type absent | Silent skip; no Finding emitted for empty types |
| DNS timeout per query | 5 s per query, 10 s total wall-clock; logs debug and skips |
| python-whois parse failure | Warning logged; no WHOIS Finding emitted |
| WHOIS rate-limiting (repeated runs) | One WHOIS call per pipeline run (root domain only) |
| Multi-value TXT (e.g. split SPF) | All values recorded in dns/txt Finding; each classified individually |
| CNAME chain depth > 1 | Only the direct CNAME target is checked; chains not followed |

---

## References

- [crt.sh](https://crt.sh/) — Certificate Transparency aggregator (Sectigo)
- [RFC 9162](https://datatracker.ietf.org/doc/html/rfc9162) — Certificate Transparency Version 2.0
- [Chrome CT Policy](https://googlechrome.github.io/CertificateTransparency/ct_policy.html) — Enforcement requirements
- [HackerTarget hostsearch](https://hackertarget.com/find-dns-host-records/) — Passive-DNS fallback
- [httpx](https://www.python-httpx.org/) — Async HTTP client (subdomain_enum)
- [dnspython](https://www.dnspython.org/) — DNS resolver library (whois_dns)
- [python-whois](https://pypi.org/project/python-whois/) — WHOIS client (whois_dns)
- [Can I take over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz) — Subdomain takeover reference
- [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208) — Sender Policy Framework (SPF)
- [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489) — DMARC specification
- [ICANN WHOIS accuracy](https://www.icann.org/resources/pages/whois-data-accuracy-2017-06-16-en) — Post-GDPR WHOIS policy
