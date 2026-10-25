# Active Reconnaissance

> **Risk level**: Low — direct, non-exploitative interaction with target systems.
> ⚠️ Written authorisation from the asset owner is **required** before running this phase.

---

## Purpose

The active phase enriches the passive asset inventory with live host data: open ports, service banners, HTTP response characteristics, TLS configuration, and WAF/CDN presence.  All interactions are observational — no vulnerability is triggered or exploited.

---

## Planned Modules

| Module file | Function | Protocol |
|---|---|---|
| `modules/active/port_scan.py` | Open port discovery | TCP/UDP |
| `modules/active/banner_grab.py` | Service version fingerprinting | TCP |
| `modules/active/http_probe.py` | HTTP status, headers, redirects | HTTP/HTTPS |
| `modules/active/waf_detect.py` | WAF / CDN heuristic detection | HTTP |
| `modules/active/tls_audit.py` | TLS version and cipher analysis | TLS |

---

## Module Interface Contract

```python
def run(assets: list[Asset], storage: ReconStorage, target: str) -> None:
    """Probe live hosts and persist enriched data to storage."""
    ...
```

- **Read** existing `assets` list (populated by passive phase).
- **Update** assets in place (e.g. `asset.ports`, `asset.ip`, `asset.tech_stack`) and
  call `storage.save_asset(asset)` to persist changes.
- **Create** `Finding` objects for significant observations (open high-risk port, outdated TLS, etc.).
- Must be rate-limited to avoid triggering DoS-like conditions.
- Must honour a configurable timeout per host.

---

## Port Scanner (`port_scan`)

TODO: Implement `modules/active/port_scan.py`.

```python
# TODO: Use asyncio.open_connection for TCP half-open probing
# TODO: Default to top-1000 ports; configurable via options
# TODO: Update asset.ports list and call storage.save_asset()
# TODO: Create Finding(severity=INFO) for each open port
```

---

## HTTP Probe (`http_probe`)

TODO: Implement `modules/active/http_probe.py`.

```python
# TODO: Use httpx.AsyncClient to probe HTTP/HTTPS on known ports
# TODO: Follow redirects and record the final URL
# TODO: Capture Server, X-Powered-By, Via headers → asset.tech_stack
# TODO: Store status code and headers as Finding evidence
```

---

## TLS Audit (`tls_audit`)

TODO: Implement `modules/active/tls_audit.py`.

```python
# TODO: Use cryptography / ssl module to connect and inspect TLS
# TODO: Record protocol version (TLS 1.0/1.1 → MEDIUM finding)
# TODO: Check certificate expiry (< 30 days → HIGH)
# TODO: Record Subject Alt Names as additional Asset domains
```

---

## Rate-Limiting Guidelines

- Maximum **10 concurrent connections** per host (configurable).
- Minimum **100 ms delay** between probe bursts.
- Respect `Retry-After` headers from HTTP 429 responses.
- Log every network error without crashing the module.

---

## References

- [httpx](https://www.python-httpx.org/) — Async HTTP client
- [asyncio networking](https://docs.python.org/3/library/asyncio-stream.html)
- [cryptography](https://cryptography.io/) — TLS certificate parsing
