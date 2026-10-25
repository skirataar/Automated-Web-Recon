"""
modules.active.port_scan
=======================
Asynchronous TCP connect port scanner for live asset surface mapping.

Technique background
--------------------

TCP Connect Scanning vs. SYN (Half-Open) Scanning
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Port scanning discovers listening network services by probing TCP destination
ports across target hosts. Two primary scanning techniques exist:

1. TCP Connect Scanning (RFC 793 standard handshake):
   - The scanner initiates a standard TCP connection using the operating
     system's Berkeley sockets API (`connect()` syscall or Python's
     `asyncio.open_connection()`).
   - The operating system performs the full 3-way handshake:
       Scanner  ─── SYN ───────►  Target
       Scanner  ◄── SYN-ACK ───   Target (Port Open)
       Scanner  ─── ACK ───────►  Target (ESTABLISHED)
   - Once established, the scanner immediately terminates the connection by
     closing the socket (sending a FIN/ACK or RST).
   - If the port is closed, the target responds with RST/ACK.
   - If the port is filtered by a firewall, packets are dropped silently or
     an ICMP unreachable message is returned, leading to a timeout.
   - Forensic Footprint: Because the connection enters the `ESTABLISHED` state,
     the remote operating system notifies the listening application via the
     `accept()` system call. Consequently, user-space daemons (web servers,
     SSH servers, databases) will generate application-level log entries (e.g.,
     "Connection established from <IP>", auth log entries, TLS handshake alerts).

2. TCP SYN Scanning ("Half-Open" / Stealth Scanning):
   - The scanner crafts raw TCP packets at the IP/TCP packet level.
   - The sequence:
       Scanner  ─── SYN ───────►  Target
       Scanner  ◄── SYN-ACK ───   Target (Port Open)
       Scanner  ─── RST ───────►  Target (Connection Aborted)
   - The scanner tears down the half-open connection with a RST packet before
     the final ACK is sent.
   - Because the 3-way handshake is never completed, the remote operating
     system's kernel does not deliver the connection to the listening
     application's socket accept queue. The application's user-space process
     never calls `accept()`, so application-level access logs typically record
     no trace of the scan (though stateful firewalls, IDS/IPS, and kernel packet
     loggers like eBPF/tcpdump observe all packets).

Why Connect Scanning is Feasible Without Raw Sockets / Root
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Operating system kernels maintain strict security boundaries around network
interfaces:
- Generating custom TCP headers with arbitrary flag sequences (e.g., sending
  an isolated SYN and suppressing the OS's normal response) requires creating
  raw sockets (`AF_INET, SOCK_RAW`).
- In POSIX environments (Linux, macOS, BSD), raw socket creation is restricted
  exclusively to the superuser (`root`) or processes endowed with the
  `CAP_NET_RAW` Linux capability. Attempting to open a raw socket as an
  unprivileged user raises `PermissionError` / `EPERM`.
- Furthermore, if an unprivileged user-space script were to send a raw SYN
  packet, the host operating system's kernel TCP stack—having no corresponding
  socket state entry in its Transmission Control Block (TCB) table—would
  automatically send a RST packet to the remote host upon receiving the incoming
  SYN-ACK, interfering with userland tracking.
- Standard TCP Connect scanning uses high-level stream sockets (`SOCK_STREAM`),
  delegating the entire handshake, sequence number tracking, and TCP state
  machine to the host kernel. This requires **zero special privileges**,
  functioning seamlessly across unprivileged user accounts, locked-down
  containers (Docker/Kubernetes non-root users), and diverse platforms
  (Linux, macOS, Windows).

Ethics, Authorization, and Responsible Testing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Active reconnaissance interacts directly with remote target systems and is
subject to strict legal and ethical obligations:

1. Written Authorization:
   Probing network ports without explicit, documented authorization from the
   asset owner may violate computer fraud and misuse statutes (e.g., the US
   Computer Fraud and Abuse Act [CFAA, 18 U.S.C. § 1030], the UK Computer
   Misuse Act 1990, Section 43/66 of the Indian Information Technology Act,
   and equivalent international laws). Always obtain signed Rules of
   Engagement (RoE) verifying explicit in-scope IP ranges and domains.

2. Fragile Device Vulnerability:
   Certain industrial control systems (ICS/SCADA), legacy operational
   technology (OT), embedded Internet of Things (IoT) devices, and outdated
   network appliances employ fragile network stacks. Rapid connection rates or
   half-open sockets can exhaust memory buffers, trigger kernel panics, or
   cause device reboots, leading to operational disruption.

3. Resource Exhaustion and Denial of Service:
   Aggressive scanning can exhaust target file descriptors, saturate database
   connection pools (e.g., maxing out MySQL/PostgreSQL client limits), or
   trigger automated defensive fail2ban / rate-limiting systems that impact
   legitimate end users.

4. Defensive Monitoring Integrity:
   Uncoordinated port scanning generates alerts on Security Information and
   Event Management (SIEM) systems and Intrusion Detection Systems (IDS/IPS),
   creating false-positive noise for security operations center (SOC) analysts
   and risking ISP or cloud provider account suspension.

5. Safe Practice Guidelines:
   - Restrict scans strictly to authorized domains and IPs.
   - Enforce concurrency limits (`concurrency` parameter) and sane timeouts.
   - Conduct scans within agreed testing windows.
   - Maintain active communication channels with the target system owners.

Module Design
-------------
- Asynchronous probing via `asyncio.open_connection()`.
- Configurable concurrency limit via `asyncio.Semaphore`.
- Configurable per-probe timeout to cleanly skip closed/filtered ports.
- Canonical default: Nmap Top 1000 TCP ports.
- Automatic IP resolution per Asset (avoids redundant DNS lookups).
- Enriches `Asset.ports` and persists to `ReconStorage`.
- Records structured `Finding` objects with contextual severity ratings.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default Concurrency & Timeout
# ---------------------------------------------------------------------------

DEFAULT_CONCURRENCY: int = 50
DEFAULT_TIMEOUT: float = 1.0

# ---------------------------------------------------------------------------
# Canonical Nmap Top 1000 TCP Ports
# Derived from global Internet survey empirical frequency distributions.
# ---------------------------------------------------------------------------

TOP_1000_PORTS: Tuple[int, ...] = (
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
    42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110,
    111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259,
    264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465,
    481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617,
    625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
    777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990,
    992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
    1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
    1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069,
    1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
    1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112,
    1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151,
    1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217,
    1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328,
    1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600,
    1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839,
    1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
    2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045,
    2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161,
    2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401,
    2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809,
    2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031,
    3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333,
    3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703,
    3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920,
    3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279,
    4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009,
    5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5269, 5280,
    5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718,
    5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907,
    5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5984, 5985, 5986, 5987, 5988, 5989, 5998, 5999,
    6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389,
    6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792,
    6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443,
    7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008,
    8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093,
    8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500,
    8600, 8649, 8651, 8652, 8699, 8701, 8800, 8873, 8888, 8899, 8901, 8902, 8903, 8954, 8994, 9000, 9001, 9002, 9003, 9009,
    9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290,
    9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929,
    9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566,
    10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238,
    14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040,
    18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800,
    25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772,
    32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292,
    40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161,
    49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673,
    52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331,
)

# ---------------------------------------------------------------------------
# Convenient Top 100 Ports for High-Speed Scans
# ---------------------------------------------------------------------------

TOP_100_PORTS: Tuple[int, ...] = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156,
)

# ---------------------------------------------------------------------------
# Common Port & Service Signatures with Risk Classifications
# Structure: port -> (service_name, severity_for_exposure, risk_description)
# ---------------------------------------------------------------------------

COMMON_SERVICES: Dict[int, Tuple[str, Severity, str]] = {
    21: ("FTP", Severity.LOW, "File Transfer Protocol; often sends credentials in cleartext"),
    22: ("SSH", Severity.INFO, "Secure Shell remote administrative service"),
    23: ("Telnet", Severity.HIGH, "Unencrypted remote terminal service; credentials exposed in cleartext"),
    25: ("SMTP", Severity.INFO, "Simple Mail Transfer Protocol mail agent"),
    53: ("DNS", Severity.INFO, "Domain Name System server"),
    69: ("TFTP", Severity.HIGH, "Trivial FTP; lacks authentication and data encryption"),
    80: ("HTTP", Severity.INFO, "World Wide Web HTTP service (unencrypted)"),
    88: ("Kerberos", Severity.INFO, "Kerberos authentication service"),
    110: ("POP3", Severity.LOW, "Post Office Protocol v3 (unencrypted cleartext mail)"),
    111: ("rpcbind", Severity.MEDIUM, "RPC portmapper; leaks system RPC programs and NFS mappings"),
    135: ("MSRPC", Severity.MEDIUM, "Microsoft RPC endpoint mapper; attack surface for Windows enumeration"),
    139: ("NetBIOS-SSN", Severity.MEDIUM, "NetBIOS Session Service; Windows network discovery"),
    143: ("IMAP", Severity.LOW, "Internet Message Access Protocol (unencrypted mail retrieval)"),
    389: ("LDAP", Severity.LOW, "Lightweight Directory Access Protocol (unencrypted directory)"),
    443: ("HTTPS", Severity.INFO, "HTTP over TLS/SSL (encrypted web service)"),
    445: ("SMB", Severity.HIGH, "Direct-hosted SMB; high-value target for remote exploits and lateral movement"),
    512: ("rexec", Severity.HIGH, "Legacy BSD remote execution; insecure cleartext authentication"),
    513: ("rlogin", Severity.HIGH, "Legacy BSD remote login; IP-based trust risks"),
    514: ("rsh", Severity.HIGH, "Legacy BSD remote shell; unencrypted and obsolete"),
    587: ("SMTP-Submission", Severity.INFO, "Mail message submission"),
    631: ("IPP/CUPS", Severity.LOW, "Common Unix Printing System"),
    636: ("LDAPS", Severity.INFO, "LDAP over TLS/SSL"),
    873: ("rsync", Severity.MEDIUM, "rsync file synchronization daemon; check for anonymous directory access"),
    993: ("IMAPS", Severity.INFO, "IMAP over TLS/SSL"),
    995: ("POP3S", Severity.INFO, "POP3 over TLS/SSL"),
    1080: ("SOCKS", Severity.MEDIUM, "SOCKS proxy; potential open relay or pivot point"),
    1433: ("MSSQL", Severity.MEDIUM, "Microsoft SQL Server database listener"),
    1521: ("Oracle-DB", Severity.MEDIUM, "Oracle Database TNS listener"),
    2049: ("NFS", Severity.HIGH, "Network File System; misconfigured exports can expose complete filesystems"),
    2375: ("Docker-REST", Severity.HIGH, "Unauthenticated Docker daemon API; allows root container takeover"),
    2376: ("Docker-TLS", Severity.MEDIUM, "Docker daemon TLS API"),
    3000: ("Node/Grafana", Severity.INFO, "Common development HTTP service / Grafana dashboard"),
    3306: ("MySQL", Severity.MEDIUM, "MySQL/MariaDB relational database listener"),
    3389: ("RDP", Severity.MEDIUM, "Remote Desktop Protocol; high-value target for brute-force attacks"),
    5000: ("Flask/Registry", Severity.INFO, "Flask dev server or Docker private registry"),
    5432: ("PostgreSQL", Severity.MEDIUM, "PostgreSQL relational database listener"),
    5900: ("VNC", Severity.HIGH, "Virtual Network Computing remote desktop; often weak or lacking authentication"),
    6379: ("Redis", Severity.HIGH, "Redis in-memory store; frequently unauthenticated, enabling remote code execution"),
    8000: ("HTTP-Alt", Severity.INFO, "Alternative HTTP / development web server"),
    8080: ("HTTP-Proxy", Severity.INFO, "Common HTTP alternative / Tomcat / Spring Boot / proxy"),
    8443: ("HTTPS-Alt", Severity.INFO, "Alternative HTTPS web service"),
    8888: ("HTTP-Alt", Severity.INFO, "Jupyter notebook / alternate HTTP web port"),
    9000: ("SonarQube/PHP", Severity.INFO, "SonarQube dashboard or PHP-FPM FastCGI listener"),
    9200: ("Elasticsearch", Severity.HIGH, "Elasticsearch HTTP REST API; frequently exposed without authentication"),
    11211: ("Memcached", Severity.HIGH, "Memcached daemon; frequently unauthenticated, prone to data theft and amplification"),
    27017: ("MongoDB", Severity.HIGH, "MongoDB database service; frequently misconfigured without authentication"),
}


# ---------------------------------------------------------------------------
# Port Parsing & Validation
# ---------------------------------------------------------------------------

def parse_ports(port_spec: Union[str, Sequence[int], Set[int], None] = None) -> List[int]:
    """Parse a port specification into a sorted, deduplicated list of valid port numbers (1-65535).

    Parameters
    ----------
    port_spec : Union[str, Sequence[int], Set[int], None]
        - If ``None``, ``"top1000"``, or ``"default"``: returns ``TOP_1000_PORTS``.
        - If ``"top100"``: returns ``TOP_100_PORTS``.
        - If string: comma-separated list of individual ports or ranges (e.g., ``"80,443,8000-8080"``).
        - If iterable of ints: validated directly.

    Returns
    -------
    List[int]
        Sorted list of unique integer port numbers within 1..65535.

    Raises
    ------
    ValueError
        If invalid port numbers or malformed syntax is supplied.
    """
    if port_spec is None:
        return sorted(list(set(TOP_1000_PORTS)))

    if isinstance(port_spec, str):
        spec_clean = port_spec.strip().lower()
        if not spec_clean:
            raise ValueError("Port specification string cannot be empty.")
        if spec_clean in {"top1000", "top-1000", "default"}:
            return sorted(list(set(TOP_1000_PORTS)))
        if spec_clean in {"top100", "top-100"}:
            return sorted(list(set(TOP_100_PORTS)))

        parsed_ports: Set[int] = set()
        for token in spec_clean.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                parts = token.split("-", 1)
                try:
                    start, end = int(parts[0].strip()), int(parts[1].strip())
                except ValueError as exc:
                    raise ValueError(f"Malformed port range {token!r}") from exc
                if start > end:
                    start, end = end, start
                for p in range(start, end + 1):
                    if not (1 <= p <= 65535):
                        raise ValueError(f"Port {p} out of valid range (1-65535)")
                    parsed_ports.add(p)
            else:
                try:
                    p = int(token)
                except ValueError as exc:
                    raise ValueError(f"Invalid port token {token!r}") from exc
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port {p} out of valid range (1-65535)")
                parsed_ports.add(p)

        if not parsed_ports:
            raise ValueError(f"No valid ports found in specification: {port_spec!r}")
        return sorted(list(parsed_ports))

    # Sequence / Set of integers
    parsed = set()
    for item in port_spec:
        if not isinstance(item, int) or not (1 <= item <= 65535):
            raise ValueError(f"Invalid port value: {item!r} (must be int 1-65535)")
        parsed.add(item)

    if not parsed:
        raise ValueError("Port list cannot be empty.")
    return sorted(list(parsed))


# ---------------------------------------------------------------------------
# DNS / Hostname Resolution
# ---------------------------------------------------------------------------

async def resolve_host(hostname: str) -> Optional[str]:
    """Resolve a hostname to an IP address asynchronously.

    If *hostname* is already a valid IPv4 or IPv6 address, it is returned immediately
    without performing a DNS lookup.

    Returns ``None`` if resolution fails.
    """
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass

    try:
        loop = asyncio.get_running_loop()
        addr_info = await loop.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        if addr_info:
            # addr_info[0][4] is sockaddr: (ip, port) for IPv4 or (ip, port, flow, scope) for IPv6
            ip_str = str(addr_info[0][4][0])
            return ip_str
    except (socket.gaierror, OSError) as exc:
        logger.debug("DNS resolution failed for %s: %s", hostname, exc)
    except Exception as exc:
        logger.debug("Unexpected error resolving %s: %s", hostname, exc)

    return None


# ---------------------------------------------------------------------------
# Core TCP Connect Probing
# ---------------------------------------------------------------------------

async def check_port(
    host: str,
    port: int,
    timeout: float = DEFAULT_TIMEOUT,
    semaphore: Optional[asyncio.Semaphore] = None,
) -> bool:
    """Attempt an asynchronous TCP connect probe to ``(host, port)``.

    Performs the full TCP 3-way handshake using standard unprivileged stream sockets.
    If the connection succeeds, the socket is cleanly closed and ``True`` is returned.
    If connection is refused, timed out, or unroutable, returns ``False``.

    Parameters
    ----------
    host : str
        Target IP address or resolvable hostname.
    port : int
        Destination TCP port (1-65535).
    timeout : float
        Connection timeout in seconds.
    semaphore : Optional[asyncio.Semaphore]
        Concurrency-limiting semaphore.
    """
    if semaphore is not None:
        async with semaphore:
            return await _do_connect(host, port, timeout)
    return await _do_connect(host, port, timeout)


async def _do_connect(host: str, port: int, timeout: float) -> bool:
    """Execute raw asyncio.open_connection wrapped with a timeout."""
    writer = None
    try:
        coro = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        return True
    except (asyncio.TimeoutError, TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception as exc:
        logger.debug("Error probing %s:%d: %s", host, port, exc)
        return False
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# High-Level Scanners
# ---------------------------------------------------------------------------

async def scan_host(
    host: str,
    ports: Optional[Union[str, Sequence[int], Set[int]]] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[int]:
    """Scan a target host across a list of ports using async TCP connect probes.

    Parameters
    ----------
    host : str
        Target IP or hostname to scan.
    ports : Optional[Union[str, Sequence[int], Set[int]]]
        Ports to probe (defaults to ``TOP_1000_PORTS``).
    concurrency : int
        Maximum simultaneous TCP connection attempts.
    timeout : float
        Timeout in seconds for each connection probe.

    Returns
    -------
    List[int]
        Sorted list of open TCP ports discovered.
    """
    port_list = parse_ports(ports)
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _probe(p: int) -> Optional[int]:
        is_open = await check_port(host, p, timeout=timeout, semaphore=semaphore)
        return p if is_open else None

    tasks = [_probe(p) for p in port_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = [r for r in results if isinstance(r, int)]
    return sorted(open_ports)


async def scan_asset(
    asset: Asset,
    ports: Optional[Union[str, Sequence[int], Set[int]]] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
) -> List[int]:
    """Scan an ``Asset`` object, automatically resolving its IP if absent.

    Parameters
    ----------
    asset : Asset
        Asset domain or IP to probe.
    ports : Optional[Union[str, Sequence[int], Set[int]]]
        Target ports (default: Top 1000).
    concurrency : int
        Max concurrent connections.
    timeout : float
        Socket connect timeout.

    Returns
    -------
    List[int]
        Sorted list of open ports found.
    """
    # Resolve IP if missing to avoid performing redundant DNS lookups for each port
    if not asset.ip:
        resolved = await resolve_host(asset.domain)
        if resolved:
            asset.ip = resolved
            logger.debug("Resolved asset %s -> %s", asset.domain, asset.ip)

    target_host = asset.ip or asset.domain
    port_list = parse_ports(ports)

    logger.info(
        "Scanning %s (%s) across %d ports [concurrency=%d, timeout=%.1fs] ...",
        asset.domain,
        target_host,
        len(port_list),
        concurrency,
        timeout,
    )

    start_time = time.monotonic()
    open_ports = await scan_host(
        host=target_host,
        ports=port_list,
        concurrency=concurrency,
        timeout=timeout,
    )
    duration = time.monotonic() - start_time

    logger.info(
        "Scan of %s (%s) finished in %.2fs: %d open port(s) found.",
        asset.domain,
        target_host,
        duration,
        len(open_ports),
    )
    return open_ports


# ---------------------------------------------------------------------------
# Finding Generation
# ---------------------------------------------------------------------------

def create_port_findings(asset: Asset, open_ports: List[int]) -> List[Finding]:
    """Generate structured Findings for discovered open ports on an Asset.

    Produces:
    1. A summary Finding (``Severity.INFO``, category ``"port-scan"``) detailing
       all open ports and their standard service names.
    2. Targeted Findings (``Severity.LOW``, ``Severity.MEDIUM``, or ``Severity.HIGH``,
       category ``"open-port"``) for exposed sensitive services such as Telnet,
       SMB, RDP, unauthenticated databases, and remote admin panels.
    """
    if not open_ports:
        return []

    findings: List[Finding] = []

    # 1. Summary Finding
    evidence_lines: List[str] = [
        f"Target Domain: {asset.domain}",
        f"Target IP:     {asset.ip or 'unresolved'}",
        f"Open Ports:    {len(open_ports)}",
        "",
        "PORT     SERVICE             RISK LEVEL  DESCRIPTION",
        "───────  ──────────────────  ──────────  ──────────────────────────────────────",
    ]

    for port in open_ports:
        svc_info = COMMON_SERVICES.get(port)
        if svc_info:
            svc_name, severity, note = svc_info
            evidence_lines.append(
                f"{port:<7}/tcp  {svc_name:<18}  {severity.value:<10}  {note}"
            )
        else:
            evidence_lines.append(
                f"{port:<7}/tcp  {'unknown':<18}  {'INFO':<10}  (Unmapped standard service)"
            )

    summary_finding = Finding(
        asset=asset,
        category="port-scan",
        severity=Severity.INFO,
        description=(
            f"Active TCP connect scan identified {len(open_ports)} open port(s) "
            f"on {asset.domain} ({asset.ip or 'unresolved'})."
        ),
        evidence="\n".join(evidence_lines),
    )
    findings.append(summary_finding)

    # 2. Individual findings for noteworthy/high-risk services
    for port in open_ports:
        svc_info = COMMON_SERVICES.get(port)
        if svc_info:
            svc_name, severity, risk_note = svc_info
            if severity >= Severity.LOW and severity != Severity.INFO:
                finding = Finding(
                    asset=asset,
                    category="open-port",
                    severity=severity,
                    description=(
                        f"Potentially sensitive service exposed on port {port}/TCP "
                        f"({svc_name}): {risk_note}"
                    ),
                    evidence=(
                        f"Host:       {asset.domain} ({asset.ip or 'unresolved'})\n"
                        f"Port:       {port}/TCP\n"
                        f"Service:    {svc_name}\n"
                        f"Severity:   {severity.value}\n"
                        f"State:      OPEN (TCP 3-way handshake established)\n"
                        f"Risk Note:  {risk_note}"
                    ),
                )
                findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Pipeline Module Entrypoint
# ---------------------------------------------------------------------------

async def run(
    assets: List[Asset],
    storage: ReconStorage,
    target: str,
    ports: Optional[Union[str, Sequence[int], Set[int]]] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """Active port scan module entrypoint conforming to the Pipeline contract.

    Parameters
    ----------
    assets : List[Asset]
        Discovered assets from prior phases (e.g. passive reconnaissance).
        If empty, attempts to load stored assets or seeds an asset for ``target``.
    storage : ReconStorage
        The active storage instance where assets and findings are persisted.
    target : str
        The primary domain or IP address under reconnaissance.
    ports : Optional[Union[str, Sequence[int], Set[int]]]
        Optional port specification. Defaults to ``TOP_1000_PORTS``.
    concurrency : int
        Maximum simultaneous TCP connections (default: 50).
    timeout : float
        Socket connect timeout in seconds (default: 1.0s).
    """
    logger.info("Starting active port scan phase for target: %r", target)

    target_assets = list(assets)
    if not target_assets:
        target_assets = storage.get_assets()

    if not target_assets:
        logger.info("No assets supplied or found in storage; creating seed asset for %r", target)
        seed_asset = Asset(domain=target, discovered_via="port_scan/seed")
        storage.save_asset(seed_asset)
        target_assets = [seed_asset]

    total_open_ports = 0
    scanned_count = 0

    for asset in target_assets:
        try:
            open_ports = await scan_asset(
                asset=asset,
                ports=ports,
                concurrency=concurrency,
                timeout=timeout,
            )
            scanned_count += 1
            total_open_ports += len(open_ports)

            # Update asset.ports with union of newly discovered and existing ports
            merged_ports = sorted(list(set(asset.ports) | set(open_ports)))
            asset.ports = merged_ports

            # Persist updated asset to storage
            storage.save_asset(asset)

            # Generate and persist Findings
            findings = create_port_findings(asset, open_ports)
            for finding in findings:
                storage.save_finding(finding)

        except Exception:
            logger.exception("Error during port scanning of asset %s", asset.domain)

    logger.info(
        "Port scan phase complete. Scanned %d asset(s), discovered %d total open port(s).",
        scanned_count,
        total_open_ports,
    )
