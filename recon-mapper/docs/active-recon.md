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
| `modules/active/port_scan.py` | Open port discovery | TCP |
| `modules/active/service_fingerprint.py` | Banner grabbing & TLS inspection (443/8443) | TCP/TLS |
| `modules/active/http_probe.py` | HTTP status, headers, redirects | HTTP/HTTPS |
| `modules/active/waf_detect.py` | WAF / CDN heuristic detection | HTTP |

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

**Status**: Implemented (`modules/active/port_scan.py`)

### Technical Overview

The port scanner performs asynchronous TCP connect probing against target hosts discovered during passive reconnaissance or seeded at pipeline invocation. It enriches each target `Asset` with an updated list of open ports (`asset.ports`), persists the changes to SQLite via `ReconStorage`, and generates structured security `Finding` records.

```python
from modules.active.port_scan import run as port_scan_run

# Pipeline execution:
await port_scan_run(assets=assets, storage=storage, target="example.com")
```

---

### TCP Connect Scanning vs. SYN (Half-Open) Scanning

Port scanning determines which TCP listening sockets are open on a remote system. The two primary techniques differ in how they interact with the TCP three-way handshake:

```
TCP Connect Scan (Full Handshake)          TCP SYN Scan (Half-Open)
─────────────────────────────────          ────────────────────────
Scanner               Target               Scanner               Target
   │                     │                    │                     │
   │─── [1] SYN ────────►│                    │─── [1] SYN ────────►│
   │◄── [2] SYN-ACK ─────│ (Port open)        │◄── [2] SYN-ACK ─────│ (Port open)
   │─── [3] ACK ────────►│ (ESTABLISHED)      │─── [3] RST ────────►│ (Aborted)
   │    [accept() called]│                    │    [No accept()]    │
   │─── [4] FIN/RST ────►│ (Teardown)         │                     │
```

#### 1. TCP Connect Scanning (`-sT` style)
- **Handshake**: Completes the full 3-way handshake (`SYN` → `SYN-ACK` → `ACK`).
- **OS Socket Queue**: The connection reaches the `ESTABLISHED` state. The remote kernel moves the connection into the listening socket's completed connection queue and notifies the listening process via `accept()`.
- **Teardown**: The scanner immediately closes the connection (`writer.close()`), transmitting a `FIN` or `RST`.
- **Forensic Footprint**: Because the socket reaches user space, listening services (e.g., Nginx, Apache, OpenSSH, PostgreSQL) log the connection in application logs (access logs, auth logs, TLS handshake errors).

#### 2. TCP SYN Scanning (`-sS` / Half-Open)
- **Handshake**: The scanner sends a `SYN` packet. When the target responds with `SYN-ACK`, the scanner immediately returns a `RST` packet instead of completing the handshake with an `ACK`.
- **OS Socket Queue**: The connection is aborted while still in the embryonic half-open state (`SYN-RECEIVED`). It never enters `ESTABLISHED`.
- **Application Impact**: The remote kernel drops the connection without delivering it to the application via `accept()`. Most userland application access logs record nothing.
- **Network Visibility**: State-tracking firewalls, Intrusion Detection Systems (IDS/IPS like Snort/Suricata), and kernel-level packet logs (eBPF/iptables) log SYN scans identically to connect scans.

---

### Why Connect Scanning is Feasible Without Raw Sockets / Root

1. **Operating System Privilege Boundaries**:
   - Constructing custom TCP/IP packets with arbitrary flags (like sending a standalone `SYN` and suppressing kernel responses) requires creating raw network sockets (`AF_INET, SOCK_RAW`).
   - On Linux, BSD, and macOS, raw socket creation requires the superuser (`root`) or the `CAP_NET_RAW` capability. Unprivileged processes fail with `PermissionError: [Errno 1] Operation not permitted`.

2. **Kernel TCP Stack Interference**:
   - In unprivileged user space, the operating system kernel maintains complete control of the TCP Transmission Control Block (TCB) table.
   - If an unprivileged user process sends a raw SYN packet, the kernel has no state entry for that socket. When the target replies with `SYN-ACK`, the host kernel assumes it is an unsolicited packet and automatically issues a `RST`, destroying the probe before user space can evaluate it.

3. **Standard Stream Sockets (`SOCK_STREAM`)**:
   - Full TCP connect scanning relies on standard Berkeley stream sockets via `asyncio.open_connection()`.
   - The operating system kernel manages all sequence numbers, window sizing, retransmissions, and state transitions.
   - **Zero elevated privileges are required**. Connect scanning runs seamlessly in unprivileged Docker containers, Kubernetes non-root pods, restricted user accounts, and across diverse operating systems (Linux, macOS, Windows).

---

### Ethics and Legal Boundaries of Active Scanning

Active port scanning sends network traffic directly to target infrastructure. It carries significant legal and operational responsibilities:

1. **Authorization & Legal Boundaries**:
   - Probing network services without prior written permission from the asset owner can violate cybercrime legislation (e.g., the US Computer Fraud and Abuse Act [CFAA, 18 U.S.C. § 1030], the UK Computer Misuse Act 1990, Section 43/66 of the Indian IT Act, and EU cybersecurity directives).
   - Only scan assets explicitly enumerated in your signed **Rules of Engagement (RoE)**.

2. **Device Fragility & Denial of Service Risks**:
   - Operational Technology (OT), SCADA/ICS hardware, medical equipment, and legacy embedded IoT appliances frequently use fragile, resource-constrained TCP/IP stacks.
   - Rapid connection spikes or malformed teardowns can exhaust internal buffers, cause kernel panics, or lock up physical hardware.
   - Connecting to database listeners (e.g., MySQL, PostgreSQL, Oracle) increments connection counters; uncontrolled concurrency can exhaust pool limits, denying service to legitimate production users.

3. **Defensive Operations & SOC Fatigue**:
   - Port scans trigger high-severity alerts on IDS/IPS, WAF, and SIEM platforms.
   - Unannounced scans generate false alarms that consume security operations center (SOC) analyst time and may result in the scanning IP being automatically blacklisted or reported to upstream hosting providers.

4. **Responsible Scanning Practices**:
   - Always confirm scope using `--scope-confirm` before executing active phases.
   - Use reasonable concurrency limits (`concurrency=50` or lower) and timeouts (`timeout=1.0s`).
   - Coordinate maintenance windows with target systems teams and have an emergency stop contact.

---

### Module Features & Implementation

`modules/active/port_scan.py` implements an enterprise-grade async scanner:

| Feature | Description |
|---|---|
| **Engine** | Native `asyncio.open_connection()` with clean stream writer teardown |
| **Default Ports** | Canonical Nmap Top-1000 TCP ports (derived from empirical Internet surveys) |
| **Presets** | `top1000` (default: 1,000 common ports), `top100` (high-speed triage: 100 ports) |
| **Custom Specs** | Arbitrary ranges and lists: `"80,443,8000-8080"` |
| **Concurrency Control** | `asyncio.Semaphore` (default: 50 concurrent connections) |
| **Timeout Handling** | Configurable per-probe timeout (default: 1.0s) for dropped/filtered packets |
| **IP Caching** | Asynchronously resolves hostnames once per asset to prevent redundant DNS lookups |
| **Asset Enrichment** | Updates `Asset.ports` with sorted union of discovered ports and upserts to `ReconStorage` |
| **Finding Generation** | Generates `Severity.INFO` summary finding with port/service matrix, plus `Severity.LOW/MEDIUM/HIGH` findings for exposed high-risk services |

#### High-Risk Service Detection Rules

The scanner automatically flags sensitive or insecure exposed services:

| Port / Service | Severity | Security Concern |
|---|---|---|
| **23 (Telnet)** | `HIGH` | Cleartext remote terminal; credentials transmitted without encryption |
| **445 (SMB)** | `HIGH` | Windows file sharing; frequent target for remote code execution and lateral movement |
| **2049 (NFS)** | `HIGH` | Network File System; misconfigured export masks expose filesystem trees |
| **2375 (Docker REST)** | `HIGH` | Unauthenticated Docker daemon API; allows root container breakout |
| **5900 (VNC)** | `HIGH` | Remote desktop; frequently configured with weak or no passwords |
| **6379 (Redis)** | `HIGH` | In-memory key-value store; often exposed without authentication, enabling RCE |
| **9200 (Elasticsearch)** | `HIGH` | Unauthenticated REST API exposing entire cluster datastores |
| **11211 (Memcached)** | `HIGH` | In-memory cache; unauthenticated data leaks and UDP amplification |
| **27017 (MongoDB)** | `HIGH` | NoSQL database; commonly misconfigured without authentication |
| **1433 / 1521 / 3306 / 5432** | `MEDIUM` | Relational databases exposed to public networks |
| **3389 (RDP)** | `MEDIUM` | Windows Remote Desktop; high-value target for brute-force attacks |
| **21 / 110 / 143** | `LOW` | Cleartext authentication protocols (FTP, POP3, IMAP) |
| **80 / 443 / 22 / 53** | `INFO` | Standard web, remote management, and naming services |

---

### Python API Usage

#### Scanning an Asset directly:
```python
import asyncio
from core.models import Asset
from modules.active.port_scan import scan_asset

asset = Asset(domain="example.com")
# Scan top 1000 ports with 50 concurrent workers and 1.0s timeout
open_ports = asyncio.run(scan_asset(asset, ports="top1000", concurrency=50, timeout=1.0))
print(f"Discovered ports: {open_ports}")
```

#### Running within the Recon Pipeline:
```python
from core.storage import ReconStorage
from core.orchestrator import Pipeline
from modules.active.port_scan import run as port_scan_run

with ReconStorage("recon.db") as storage:
    pipeline = Pipeline(storage=storage, target="example.com", phases_to_run=["active"])
    pipeline.register("active", port_scan_run)
    pipeline.run()
```

---

## Service Fingerprinting & TLS Inspection (`service_fingerprint`)

**Status**: Implemented (`modules/active/service_fingerprint.py`)

### Technical Overview

The service fingerprinting module runs directly after port scanning. For each discovered open port on an `Asset`, it performs banner grabbing to identify running daemon software and version numbers. For HTTPS/TLS ports (`443`, `8443`), it establishes an SSL/TLS handshake to extract certificate authority (issuer), validity dates (expiry), Subject Alternative Names (SANs), protocol versions, and cipher suites.

Discovered technologies are merged into `asset.tech_stack`, and observations are persisted to SQLite as structured `Finding` records.

```python
from modules.active.service_fingerprint import run as service_fingerprint_run

# Pipeline execution:
await service_fingerprint_run(assets=assets, storage=storage, target="example.com")
```

---

### How Banner Grabbing Works

A banner is an initial informational string transmitted by a network daemon upon connection. Banner grabbing inspects this data to discover the exact software name, version, architecture, and host operating system.

```
Passive (Unsolicited) Banner Flow          Active (Solicited) Probe Flow
─────────────────────────────────          ─────────────────────────────
Client                 Server              Client                 Server
   │                     │                    │                     │
   │─── TCP Connect ────►│                    │─── TCP Connect ────►│
   │◄── "220 vsFTPd" ────│ (Auto-greeting)    │    (Silent/Waiting) │
   │                     │                    │─── "HEAD / HTTP/1.1"►│ (Stimulus)
   │                     │                    │◄── "Server: nginx" ──│ (Headers)
```

1. **Unsolicited (Passive) Banners**:
   - Protocols such as SSH, FTP, SMTP, and MySQL announce themselves immediately upon connection:
     * **SSH**: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` (identifies protocol 2.0, OpenSSH 8.9p1, Ubuntu Linux)
     * **FTP**: `220 (vsFTPd 3.0.3)` or `220 ProFTPD 1.3.5 Server`
     * **SMTP**: `220 mail.example.com ESMTP Postfix (Ubuntu)`
   - The scanner connects and pauses briefly (up to 800ms) to read any immediate greeting.

2. **Active (Solicited) Probes**:
   - Silent services (web servers, databases, caching proxies) wait for client input before responding.
   - If no unsolicited greeting arrives, the scanner sends a benign protocol stimulus:
     * **Web services (80, 443, 8080, 8443, etc.)**: Sends `HEAD / HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\n\r\n`. The server responds with HTTP response headers:
       `Server: nginx/1.24.0`
       `X-Powered-By: PHP/8.2.1`
     * **Redis (6379)**: Sends `PING\r\n`; server responds with `+PONG` or `-NOAUTH`.
     * **Generic TCP**: Sends `\r\n\r\n` to elicit error banners (e.g. syntax errors disclosing daemon name).

---

### What a TLS Certificate's SAN, Issuer, and Expiry Reveal

For TLS services on ports `443` and `8443`, the X.509 certificate exposes critical infrastructure data:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      X.509 TLS Certificate                             │
├────────────────────────────────────────────────────────────────────────┤
│ Subject:  CN=api.example.com, O=Example Corporation                    │
│ Issuer:   CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert    │
│ Validity: 2026-01-01 00:00:00 UTC  ──►  2027-01-01 00:00:00 UTC        │
│ Protocol: TLSv1.3  |  Cipher: TLS_AES_256_GCM_SHA384 (256 bits)       │
├────────────────────────────────────────────────────────────────────────┤
│ Subject Alternative Names (SANs):                                      │
│   • api.example.com            • vpn.internal.example.com              │
│   • admin.stage.example.com    • legacy-portal.example.com             │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Subject Alternative Names (SAN)**:
   - Modern TLS standards (RFC 5280) deprecate Common Name (CN) in favor of the SAN extension.
   - **Attack Surface Discovery**: Multi-tenant or wildcard certificates often bundle internal hostnames, administrative consoles, and staging systems that have no public DNS records (e.g., `vpn.internal.example.com`, `admin-stage.example.com`).
   - **Infrastructure Scope**: Shared certificates reveal sister domains, subsidiaries, and cloud provider hosting aliases.

2. **Issuer (Certificate Authority - CA)**:
   - **Cloud Proxy / CDN Detection**: Certificates issued by "Cloudflare Inc" or "Amazon" indicate the asset sits behind an edge reverse proxy rather than direct origin hosting.
   - **Internal Enterprise PKI**: An issuer such as `CN=Corp-Root-CA` or `O=Acme Internal CA` indicates an internal enterprise system unintentionally exposed to the Internet.
   - **Self-Signed Certificates (`Issuer == Subject`)**: Signals development systems, unmanaged shadow IT, or embedded hardware with absent certificate lifecycle controls.

3. **Validity & Expiry (`notBefore` / `notAfter`)**:
   - **Expired Certificates**: Points to unmaintained, abandoned, or decommissioned "zombie" servers. These systems are prime candidates for critical unpatched vulnerabilities.
   - **Certificates Expiring in < 30 Days**: Highlights operational neglect or failure in automated ACME renewal pipelines.
   - **Creation Date**: Reveals when infrastructure was provisioned or updated.

4. **Protocol Version & Cipher Suite**:
   - Identifies deprecated protocols (`TLS 1.0`, `TLS 1.1`, `SSLv3`) vulnerable to cryptographic downgrade attacks (BEAST, POODLE).
   - Validates whether modern cipher suites (AEAD ciphers with Forward Secrecy) are enforced.

---

### Why Version Strings in Banners Matter for CVE Matching

Version strings captured from banners are the essential inputs for automated vulnerability correlation:

1. **Common Platform Enumeration (CPE) Mapping**:
   - Banners normalize into standardized CPE 2.3 identifiers:
     * `Apache/2.4.49` → `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*`
     * `OpenSSH_7.4p1` → `cpe:2.3:a:openbsd:openssh:7.4p1:*:*:*:*:*:*:*`

2. **Vulnerability Database Correlation**:
   - The National Vulnerability Database (NVD), GitHub Advisory Database, and vendor trackers index CVEs by vulnerable version ranges.
   - Exact version numbers immediately link to known exploits:
     * `Apache/2.4.49` → **CVE-2021-41773** (Path Traversal and Remote Code Execution)
     * `Apache/2.4.50` → **CVE-2021-42013** (Incomplete fix for CVE-2021-41773)
     * `OpenSSH_7.4` → **CVE-2018-15473** (User enumeration via malformed auth packets)
     * `ProFTPD 1.3.5` → **CVE-2015-3306** (`mod_copy` unauthenticated arbitrary file copy)

3. **Defense Verification**:
   - Discrepancies between banners and HTTP behavior highlight WAF obfuscation (e.g. `Server: Apache` returned by an Nginx reverse proxy) or decoy honeypots.

---

### Module Features & Severity Classification

`modules/active/service_fingerprint.py` generates structured observations:

| Finding Category | Severity | Trigger Condition |
|---|---|---|
| `tls` | `HIGH` | TLS certificate is expired (`now > not_after`) |
| `tls` | `MEDIUM` | TLS certificate expires within 30 days |
| `tls` | `MEDIUM` | Service uses deprecated protocol (`TLSv1.0`, `TLSv1.1`, `SSLv3`) |
| `tls` | `LOW` | Self-signed certificate on public domain |
| `tls` | `INFO` | Valid modern TLS certificate (TLS 1.2/1.3, unexpired, trusted) |
| `service-fingerprint` | `INFO` | Service banner captured, software/version extracted |

---

### Python API Usage

#### Inspecting an Asset directly:
```python
import asyncio
from core.models import Asset
from modules.active.service_fingerprint import fingerprint_asset

asset = Asset(domain="example.com", ip="93.184.216.34", ports=[80, 443, 22])
findings = asyncio.run(fingerprint_asset(asset, timeout=2.0, tls_ports=[443]))

print(f"Enriched tech stack: {asset.tech_stack}")
for f in findings:
    print(f"[{f.severity.value}] {f.description}")
```

#### Running within the Recon Pipeline:
```python
from core.storage import ReconStorage
from core.orchestrator import Pipeline
from modules.active.port_scan import run as port_scan_run
from modules.active.service_fingerprint import run as service_fingerprint_run

with ReconStorage("recon.db") as storage:
    pipeline = Pipeline(storage=storage, target="example.com", phases_to_run=["active"])
    pipeline.register("active", port_scan_run)
    pipeline.register("active", service_fingerprint_run)
    pipeline.run()
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
