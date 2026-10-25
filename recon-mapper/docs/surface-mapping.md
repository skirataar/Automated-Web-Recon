# Surface Mapping

> **Risk level**: Moderate — spider and brute-force traffic is generated against the target.
> ⚠️ Written authorisation from the asset owner is **required** before running this phase.

---

## Purpose

The surface-mapping phase enumerates the target's exposed *functionality*: every URL, form, API endpoint, and file path that an attacker could interact with.  This data feeds directly into Phase 4 (vuln_indicators) and forms the core of the attack-surface model.

---

## Planned Modules

| Module file | Function | Technique |
|---|---|---|
| `modules/surface/endpoint_crawler.py` | Recursive URL and form discovery | Depth-limited spider |
| `modules/surface/js_analyzer.py` | Endpoint and secret extraction from JS | Static analysis |
| `modules/surface/api_discovery.py` | REST / GraphQL / gRPC surface | Spec probing + pattern matching |
| `modules/surface/dir_brute.py` | Common path discovery | Wordlist probing |
| `modules/surface/param_miner.py` | Hidden HTTP parameter discovery | Reflection analysis |

---

## Module Interface Contract

```python
def run(assets: list[Asset], storage: ReconStorage, target: str) -> None:
    """Enumerate exposed functionality and persist findings."""
    ...
```

- Assets arriving here already have `ip`, `ports`, and `tech_stack` populated by Phase 2.
- Create `Finding` objects for each discovered endpoint, form, or notable path.
- Use `category="endpoint"`, `category="js-secret"`, `category="api"`, etc.
- Severity guidance: hidden admin paths → `HIGH`; ordinary endpoints → `INFO`.

---

## Endpoint Crawler (`endpoint_crawler`)

TODO: Implement `modules/surface/endpoint_crawler.py`.

```python
# TODO: Use httpx + BeautifulSoup to extract href, src, action attributes
# TODO: Depth-limit: default 3; configurable via options
# TODO: Scope-limit: only crawl sub-domains of the target
# TODO: Store each URL as a Finding with category="endpoint"
```

---

## JavaScript Analyser (`js_analyzer`)

TODO: Implement `modules/surface/js_analyzer.py`.

```python
# TODO: Collect all <script src="..."> URLs from crawled pages
# TODO: Fetch JS bundles via httpx
# TODO: Use regex to extract:
#         - /api/... path patterns
#         - AWS key patterns (AKIA...)
#         - Generic secret patterns (password=, apiKey=, token=)
# TODO: Severity: leaked secret → HIGH; path discovery → INFO
```

---

## API Discovery (`api_discovery`)

TODO: Implement `modules/surface/api_discovery.py`.

```python
# TODO: Probe common spec paths: /openapi.json, /swagger.json,
#       /graphql, /api/schema, /.well-known/...
# TODO: If GraphQL: send introspection query
# TODO: Record discovered spec as evidence in a Finding
```

---

## Directory Brute-Force (`dir_brute`)

TODO: Implement `modules/surface/dir_brute.py`.

```python
# TODO: Accept a wordlist path (default: built-in minimal wordlist)
# TODO: Use httpx with rate-limiting to probe each path
# TODO: 200/301/302/403 → record as Finding; 404 → skip
# TODO: Respect --rate-limit option
```

---

## References

- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) — HTML parsing
- [httpx](https://www.python-httpx.org/) — Async HTTP
- Common wordlists: [SecLists](https://github.com/danielmiessler/SecLists)
