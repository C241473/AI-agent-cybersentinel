"""
CyberSentinel AI - Threat Intelligence & CVE Advisory System
Provides threat advisory data, CVSS metrics, exploit vector analysis, and SOC playbooks.
"""

from typing import Dict, Any, List
import requests

# Offline Knowledge Base of high-impact historical & modern CVEs
NOTABLE_CVES = {
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "name": "Log4Shell (Apache Log4j RCE)",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_software": "Apache Log4j 2.0-beta9 to 2.14.1",
        "attack_vector": "Network (JNDI lookup injection)",
        "description": "JNDI lookup feature in Log4j allows remote attackers to execute arbitrary code by passing ${jndi:ldap://...} strings into logged inputs.",
        "mitigation_steps": [
            "Upgrade to Log4j 2.17.1 or higher.",
            "Set system property log4j2.formatMsgNoLookups=true on JVM startup.",
            "Remove JndiLookup class from classpath: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class"
        ],
        "mitre_technique": "T1190"
    },
    "CVE-2022-22965": {
        "cve_id": "CVE-2022-22965",
        "name": "Spring4Shell (Spring Framework RCE)",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": "Spring Framework versions 5.3.0 to 5.3.17, 5.2.0 to 5.2.19 running on JDK 9+",
        "attack_vector": "HTTP request parameter binding",
        "description": "Data binding flaw allows access to Tomcat ClassLoader properties via request parameters, leading to web shell upload.",
        "mitigation_steps": [
            "Upgrade Spring Framework to version 5.3.18+ or 5.2.20+.",
            "Disallow field patterns via WebDataBinder setDisallowedFields."
        ],
        "mitre_technique": "T1190"
    },
    "CVE-2023-34362": {
        "cve_id": "CVE-2023-34362",
        "name": "MOVEit Transfer SQL Injection / RCE",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": "Progress Software MOVEit Transfer",
        "attack_vector": "Web application SQL Injection",
        "description": "SQL injection in MOVEit Transfer web application leading to privilege escalation, session hijacking, and unauthorized database exfiltration.",
        "mitigation_steps": [
            "Apply vendor patches immediately.",
            "Block HTTP/HTTPS traffic on ports 80 and 443 to the MOVEit Transfer server until patched.",
            "Audit for unrecognized files in C:\\MOVEitTransfer\\wwwroot."
        ],
        "mitre_technique": "T1190"
    },
    "CVE-2023-4966": {
        "cve_id": "CVE-2023-4966",
        "name": "Citrix Bleed (NetScaler ADC / Gateway Information Disclosure)",
        "cvss_score": 9.4,
        "severity": "CRITICAL",
        "affected_software": "Citrix NetScaler ADC and NetScaler Gateway",
        "attack_vector": "Buffer overflow in OpenID Connect endpoint",
        "description": "Unauthenticated memory buffer over-read returns active session tokens, allowing attackers to hijack established MFA sessions.",
        "mitigation_steps": [
            "Update NetScaler firmware to the fixed version immediately.",
            "Terminate and invalidate all active user sessions with 'kill aaa session -all'."
        ],
        "mitre_technique": "T1552"
    },
    "CVE-2024-3094": {
        "cve_id": "CVE-2024-3094",
        "name": "XZ Utils Backdoor (Supply Chain Compromise)",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_software": "xz-utils versions 5.6.0 and 5.6.1",
        "attack_vector": "Malicious upstream build artifact injection into liblzma",
        "description": "Backdoor injected into upstream tarballs modifies sshd authentication function via IFUNC, allowing remote unauthorized authentication.",
        "mitigation_steps": [
            "Immediately downgrade xz-utils to version 5.4.x or clean upstream release.",
            "Audit systems using vulnerable Linux distributions (Debian sid/Fedora 40/41 raw)."
        ],
        "mitre_technique": "T1195.001"
    },
    "CVE-2017-0144": {
        "cve_id": "CVE-2017-0144",
        "name": "EternalBlue (MS17-010 SMB Remote Code Execution)",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_software": "Microsoft Windows SMBv1 server",
        "attack_vector": "SMBv1 packet buffer handling flaw",
        "description": "Remote code execution flaw in SMBv1 exploited by WannaCry and NotPetya ransomware to spread across enterprise networks.",
        "mitigation_steps": [
            "Disable SMBv1 completely across all Windows systems.",
            "Apply Microsoft security patch MS17-010.",
            "Block port 445 at boundary firewalls."
        ],
        "mitre_technique": "T1210"
    }
}

class CVEAdvisory:
    """Threat intelligence and CVE advisory lookup tool."""

    def lookup(self, query: str) -> Dict[str, Any]:
        """Look up vulnerability details by CVE ID or keyword."""
        clean_query = query.strip().upper()
        
        # Check built-in database first
        if clean_query in NOTABLE_CVES:
            return {
                "source": "Local Threat Intelligence Engine",
                "status": "FOUND",
                "cve": NOTABLE_CVES[clean_query]
            }

        # Fuzzy search in built-in database
        for cve_id, data in NOTABLE_CVES.items():
            if clean_query in cve_id or clean_query in data["name"].upper():
                return {
                    "source": "Local Threat Intelligence Engine",
                    "status": "FOUND",
                    "cve": data
                }

        # Try live query via OSV.dev (Open Source Vulnerabilities) API
        try:
            resp = requests.get(f"https://api.osv.dev/v1/vulns/{clean_query}", timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "source": "OSV Global Vulnerability Database",
                    "status": "FOUND",
                    "cve": {
                        "cve_id": data.get("id"),
                        "name": data.get("summary", "Vulnerability Advisory"),
                        "cvss_score": 7.5,
                        "severity": "HIGH",
                        "affected_software": ", ".join([p.get("package", {}).get("name", "") for p in data.get("affected", [])[:3]]),
                        "attack_vector": "Network",
                        "description": data.get("details", "No description provided.")[:300] + "...",
                        "mitigation_steps": [
                            "Update affected packages to the latest patched releases.",
                            "Consult vendor advisory."
                        ],
                        "mitre_technique": "T1190"
                    }
                }
        except Exception:
            pass

        return {
            "source": "None",
            "status": "NOT_FOUND",
            "message": f"No immediate CVE record found for '{query}'. Ensure format is CVE-YYYY-NNNN or query a known threat name."
        }
