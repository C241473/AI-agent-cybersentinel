"""
CyberSentinel AI - Security Operations Log Analyzer
Parses and inspects server access logs (Apache/Nginx/Common/Combined/Custom) to detect:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Directory/Path Traversal & LFI
- Command Injection / Remote Code Execution (RCE)
- Security Scanners (sqlmap, nikto, gobuster, nmap)
- Sensitive files probing (.env, .git, config, backups)
- Brute Force & Rate Limit Breaches
"""

import re
import urllib.parse
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any
from tools.mitre_mapper import map_threat_to_mitre

# Common Log Format regex: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
LOG_REGEX = re.compile(
    r'(?P<ip>[\d\.:a-fA-F]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<authuser>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s*(?P<protocol>[^"]+)?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<useragent>[^"]*)")?'
)

# Detection Pattern Signatures
ATTACK_SIGNATURES = [
    {
        "type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(\%27|')\s*(or|and)\s*(\d+=\d+|'[^']*'='[^']*)",
            r"(?i)union(\s+all)?\s+select",
            r"(?i)order\s+by\s+\d+",
            r"(?i)(sleep\(|waitfor\s+delay|benchmark\()",
            r"(?i)information_schema",
            r"(?i)(drop|truncate|alter)\s+table",
            r"(?i)--\s*$",
            r"(?i)/\*\!.*\*/"
        ],
        "description": "SQL Injection attempt detected in request URI or query parameters"
    },
    {
        "type": "XSS",
        "severity": "HIGH",
        "patterns": [
            r"(?i)<script[^>]*>",
            r"(?i)javascript:\s*",
            r"(?i)onload\s*=",
            r"(?i)onerror\s*=",
            r"(?i)document\.cookie",
            r"(?i)alert\(.*\)",
            r"(?i)<iframe[^>]*>",
            r"(?i)%3Cscript%3E"
        ],
        "description": "Cross-Site Scripting (XSS) payload payload detected"
    },
    {
        "type": "PATH_TRAVERSAL",
        "severity": "HIGH",
        "patterns": [
            r"(\.\./|\.\.\\)",
            r"(%2e%2e%2f|%2e%2e\/)",
            r"/etc/passwd",
            r"/etc/shadow",
            r"win\.ini",
            r"system32/cmd\.exe",
            r"boot\.ini"
        ],
        "description": "Directory Traversal / Local File Inclusion (LFI) attempt detected"
    },
    {
        "type": "RCE_COMMAND_INJECTION",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(;|\||\`|\$\().*(bash|sh|cmd\.exe|powershell|whoami|cat\s+/etc|id|curl\s+http|wget\s+)",
            r"(?i)/bin/bash",
            r"(?i)/bin/sh"
        ],
        "description": "Remote Command Execution / Shell injection attempt"
    },
    {
        "type": "SENSITIVE_FILE_PROBING",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)\.env",
            r"(?i)\.git/(config|HEAD)",
            r"(?i)wp-config\.php",
            r"(?i)phpinfo\.php",
            r"(?i)backup(\.sql|\.tar|\.zip)",
            r"(?i)id_rsa",
            r"(?i)database\.sqlite",
            r"(?i)server-status"
        ],
        "description": "Probing for sensitive configuration files, keys, or source control data"
    },
    {
        "type": "RECON_SCANNER",
        "severity": "MEDIUM",
        "patterns": [
            r"(?i)sqlmap",
            r"(?i)nikto",
            r"(?i)nmap",
            r"(?i)gobuster",
            r"(?i)dirbuster",
            r"(?i)masscan",
            r"(?i)acunetix",
            r"(?i)wpscan"
        ],
        "description": "Automated security scanning tool signature identified in User-Agent or URI"
    }
]

class LogAnalyzer:
    """SOC Log Inspector for detecting attacks and anomalous activity."""

    def __init__(self, brute_force_threshold: int = 5):
        self.brute_force_threshold = brute_force_threshold

    def parse_line(self, line: str) -> Dict[str, Any]:
        """Parse a single log line into structured fields."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        match = LOG_REGEX.match(line)
        if match:
            data = match.groupdict()
            return {
                "ip": data.get("ip"),
                "timestamp": data.get("timestamp"),
                "method": data.get("method"),
                "uri": data.get("uri"),
                "status": int(data.get("status") or 0),
                "bytes": data.get("bytes"),
                "user_agent": data.get("useragent") or "-",
                "raw": line
            }
        
        # Fallback simple extractor if custom log format
        parts = line.split()
        if len(parts) >= 6:
            ip = parts[0]
            method = "GET"
            uri = "/"
            status = 200
            for i, p in enumerate(parts):
                if p in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]:
                    method = p
                    if i + 1 < len(parts):
                        uri = parts[i+1]
                if p.isdigit() and len(p) == 3 and int(p) in range(100, 600):
                    status = int(p)
            return {
                "ip": ip,
                "timestamp": "N/A",
                "method": method,
                "uri": uri,
                "status": status,
                "bytes": "0",
                "user_agent": "-",
                "raw": line
            }
        return None

    def analyze_log_content(self, log_content: str) -> Dict[str, Any]:
        """Analyze multi-line log string and detect all threats."""
        lines = log_content.strip().splitlines()
        
        total_requests = 0
        parsed_entries = []
        alerts = []
        ip_stats = defaultdict(lambda: {
            "requests": 0,
            "failed_auth": 0,
            "attacks": [],
            "status_codes": Counter(),
            "user_agents": set()
        })
        
        for line_num, line in enumerate(lines, 1):
            entry = self.parse_line(line)
            if not entry:
                continue

            total_requests += 1
            ip = entry["ip"]
            uri = entry["uri"]
            decoded_uri = urllib.parse.unquote(uri)
            user_agent = entry["user_agent"]
            status = entry["status"]

            stats = ip_stats[ip]
            stats["requests"] += 1
            stats["status_codes"][status] += 1
            if user_agent != "-":
                stats["user_agents"].add(user_agent)

            if status in (401, 403):
                stats["failed_auth"] += 1

            # Check attack signatures
            combined_search_target = f"{uri} {decoded_uri} {user_agent}"
            
            matched_threats = set()
            for sig in ATTACK_SIGNATURES:
                threat_type = sig["type"]
                for pattern in sig["patterns"]:
                    if re.search(pattern, combined_search_target):
                        if threat_type not in matched_threats:
                            matched_threats.add(threat_type)
                            mitre = map_threat_to_mitre(threat_type)
                            alert = {
                                "line_number": line_num,
                                "timestamp": entry["timestamp"],
                                "ip": ip,
                                "method": entry["method"],
                                "uri": uri,
                                "status": status,
                                "threat_type": threat_type,
                                "severity": sig["severity"],
                                "description": sig["description"],
                                "mitre": mitre,
                                "raw_sample": line[:150] + ("..." if len(line) > 150 else "")
                            }
                            alerts.append(alert)
                            stats["attacks"].append(threat_type)

        # Check for Brute Force threshold breaches
        for ip, stats in ip_stats.items():
            if stats["failed_auth"] >= self.brute_force_threshold:
                mitre = map_threat_to_mitre("BRUTE_FORCE")
                alerts.append({
                    "line_number": 0,
                    "timestamp": "Aggregate",
                    "ip": ip,
                    "method": "MULTIPLE",
                    "uri": "/login (repeated failures)",
                    "status": 401,
                    "threat_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "description": f"Potential Brute Force / Credential Stuffing detected ({stats['failed_auth']} failed attempts)",
                    "mitre": mitre,
                    "raw_sample": f"{stats['failed_auth']} failed authentications from {ip}"
                })
                stats["attacks"].append("BRUTE_FORCE")

        # Severity breakdown
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        threat_type_counts = Counter()
        for alert in alerts:
            sev = alert.get("severity", "LOW")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            threat_type_counts[alert["threat_type"]] += 1

        # Calculate Attacker IPs ranking
        attacker_ips = []
        for ip, stats in sorted(ip_stats.items(), key=lambda item: len(item[1]["attacks"]) + item[1]["failed_auth"], reverse=True):
            if stats["attacks"] or stats["failed_auth"] >= self.brute_force_threshold:
                attacker_ips.append({
                    "ip": ip,
                    "total_requests": stats["requests"],
                    "failed_auth": stats["failed_auth"],
                    "threat_types": list(set(stats["attacks"])),
                    "recommended_action": f"iptables -A INPUT -s {ip} -j DROP",
                    "threat_score": min(100, (len(stats["attacks"]) * 20) + (stats["failed_auth"] * 5))
                })

        return {
            "summary": {
                "total_log_lines": len(lines),
                "total_requests": total_requests,
                "unique_ips": len(ip_stats),
                "total_threats_detected": len(alerts),
                "severity_breakdown": severity_counts,
                "threat_type_breakdown": dict(threat_type_counts)
            },
            "alerts": alerts,
            "top_attacker_ips": attacker_ips[:10]
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a log file from path."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.analyze_log_content(content)
        except Exception as e:
            return {
                "error": str(e),
                "summary": {},
                "alerts": [],
                "top_attacker_ips": []
            }
