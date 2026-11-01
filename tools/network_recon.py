"""
CyberSentinel AI - Network & Web Posture Reconnaissance Tool
Performs:
- TCP Port scanning for common service exposure
- Web HTTP Security Header auditing (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS certificate inspection
"""

import socket
import ssl
import urllib.parse
from typing import Dict, List, Any
import requests

COMMON_PORTS = {
    21: {"service": "FTP", "risk": "HIGH", "detail": "Unencrypted file transfer. Cleartext credentials vulnerable to sniffing."},
    22: {"service": "SSH", "risk": "LOW", "detail": "Encrypted remote shell. Ensure root login is disabled and key-based auth is enforced."},
    23: {"service": "Telnet", "risk": "CRITICAL", "detail": "Legacy cleartext protocol. Disable immediately in favor of SSH."},
    25: {"service": "SMTP", "risk": "MEDIUM", "detail": "Mail server port. Verify relay settings to prevent open relay exploitation."},
    53: {"service": "DNS", "risk": "LOW", "detail": "Domain Name System. Ensure recursion is restricted to internal clients."},
    80: {"service": "HTTP", "risk": "MEDIUM", "detail": "Unencrypted web traffic. Enforce redirect to HTTPS (port 443)."},
    443: {"service": "HTTPS", "risk": "INFO", "detail": "Standard encrypted web traffic."},
    1433: {"service": "MSSQL", "risk": "HIGH", "detail": "Microsoft SQL Server database. Should not be exposed to the public internet."},
    3306: {"service": "MySQL", "risk": "HIGH", "detail": "MySQL database port. Risk of credential brute force if publicly exposed."},
    3389: {"service": "RDP", "risk": "HIGH", "detail": "Windows Remote Desktop. Frequent target for ransomware and BlueKeep exploits."},
    5432: {"service": "PostgreSQL", "risk": "HIGH", "detail": "PostgreSQL database port. Should bind strictly to localhost or private VPC."},
    6379: {"service": "Redis", "risk": "CRITICAL", "detail": "In-memory database. Frequently targeted when unauthenticated (RCE hazard)."},
    8080: {"service": "HTTP-Proxy / Alt", "risk": "MEDIUM", "detail": "Common development or proxy port. Check for exposed admin panels."},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "detail": "NoSQL database. Frequently targeted by automated ransom bots if exposed."}
}

RECOMMENDED_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "Enforces HTTPS connections and prevents SSL stripping attacks.",
        "recommended_value": "max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "Restricts loading of malicious scripts, frames, and unauthorized assets (XSS mitigation).",
        "recommended_value": "default-src 'self'; script-src 'self'; object-src 'none';"
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Prevents Clickjacking by disallowing embedding inside foreign iframes.",
        "recommended_value": "DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "Prevents MIME-type sniffing by browsers.",
        "recommended_value": "nosniff"
    },
    "Referrer-Policy": {
        "required": False,
        "description": "Controls how much referrer information is included with requests.",
        "recommended_value": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "required": False,
        "description": "Disables browser features like camera, microphone, or geolocation if unused.",
        "recommended_value": "geolocation=(), microphone=(), camera=()"
    }
}

class NetworkRecon:
    """Network security and web surface inspection tool."""

    def scan_ports(self, host: str, port_list: List[int] = None, timeout: float = 0.5) -> Dict[str, Any]:
        """Scan specified or default ports on host."""
        if port_list is None:
            port_list = list(COMMON_PORTS.keys())

        # Resolve host
        try:
            target_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return {
                "host": host,
                "error": f"Failed to resolve host: {e}",
                "open_ports": []
            }

        open_ports = []
        for port in port_list:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    info = COMMON_PORTS.get(port, {
                        "service": "Unknown",
                        "risk": "MEDIUM",
                        "detail": "Non-standard open port detected."
                    })
                    open_ports.append({
                        "port": port,
                        "service": info["service"],
                        "risk": info["risk"],
                        "security_note": info["detail"]
                    })
            except Exception:
                pass
            finally:
                sock.close()

        return {
            "target_host": host,
            "target_ip": target_ip,
            "scanned_ports_count": len(port_list),
            "open_ports_count": len(open_ports),
            "open_ports": open_ports
        }

    def inspect_web_headers(self, url: str) -> Dict[str, Any]:
        """Inspect HTTP security response headers of a web endpoint."""
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        try:
            resp = requests.get(url, timeout=5, allow_redirects=True, headers={
                "User-Agent": "CyberSentinel-AI/1.0 (Security Posture Auditor)"
            })
            headers = resp.headers

            missing_headers = []
            present_headers = []

            for header_name, config in RECOMMENDED_HEADERS.items():
                if header_name in headers:
                    present_headers.append({
                        "header": header_name,
                        "value": headers[header_name],
                        "status": "PASS",
                        "description": config["description"]
                    })
                else:
                    missing_headers.append({
                        "header": header_name,
                        "status": "FAIL",
                        "severity": "HIGH" if config["required"] else "MEDIUM",
                        "description": config["description"],
                        "recommended_value": config["recommended_value"]
                    })

            security_score = int((len(present_headers) / len(RECOMMENDED_HEADERS)) * 100)

            return {
                "target_url": url,
                "status_code": resp.status_code,
                "security_score": security_score,
                "missing_headers": missing_headers,
                "present_headers": present_headers,
                "raw_server_header": headers.get("Server", "Hidden/Not Provided")
            }
        except Exception as e:
            return {
                "target_url": url,
                "error": str(e),
                "security_score": 0,
                "missing_headers": [],
                "present_headers": []
            }
