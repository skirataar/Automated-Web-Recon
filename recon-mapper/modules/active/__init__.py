"""
modules.active
==============
Active reconnaissance modules (direct, non-exploitative interaction with target).

⚠️  Always obtain written authorization before running active modules.

Implemented modules:
  - port_scan           : TCP connect port scanning (asyncio-based, top-1000 default)
  - service_fingerprint : Banner grabbing, technology identification, and TLS inspection

Planned modules (TODO – implement individually):
  - http_probe          : HTTP/HTTPS probing, redirect chains, status codes
  - waf_detect          : Web Application Firewall detection heuristics
"""

from modules.active.port_scan import run as port_scan_run
from modules.active.service_fingerprint import run as service_fingerprint_run

__all__ = ["port_scan_run", "service_fingerprint_run"]
