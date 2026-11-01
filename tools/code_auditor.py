"""
CyberSentinel AI - Static Application Security Testing (SAST) Code Auditor
Scans source code for critical security vulnerabilities, misconfigurations, and credential leaks.
"""

import re
from typing import List, Dict, Any
from tools.mitre_mapper import map_threat_to_mitre

CODE_VULN_RULES = [
    {
        "id": "SEC-001",
        "name": "Hardcoded Secret / API Key",
        "threat_type": "HARDCODED_SECRET",
        "severity": "CRITICAL",
        "cvss": 8.9,
        "patterns": [
            r"(?i)(api[_-]?key|secret|password|passwd|auth[_-]?token|access[_-]?token)\s*=\s*['\"][A-Za-z0-9_\-\/+=]{12,}['\"]",
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
            r"ghp_[0-9a-zA-Z]{36}", # GitHub Personal Access Token
            r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" # JWT
        ],
        "description": "Hardcoded credential or sensitive secret discovered in source code.",
        "remediation": "Move secrets to environment variables (.env) or use a secure vault service (AWS Secrets Manager, HashiCorp Vault)."
    },
    {
        "id": "SEC-002",
        "name": "SQL Injection via String Concatenation",
        "threat_type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "cvss": 9.3,
        "patterns": [
            r"(?i)(execute|cursor\.execute|raw)\s*\(\s*f['\"].*(SELECT|INSERT|UPDATE|DELETE).*\{.*\}",
            r"(?i)(execute|cursor\.execute|raw)\s*\(\s*['\"].*(SELECT|INSERT|UPDATE|DELETE).*['\"]\s*%",
            r"(?i)(execute|cursor\.execute|raw)\s*\(\s*['\"].*(SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\+\s*[a-zA-Z_]"
        ],
        "description": "Unsanitized user variables concatenated directly into SQL queries.",
        "remediation": "Use parameterized queries with placeholders: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    },
    {
        "id": "SEC-003",
        "name": "Command Injection / Insecure Subprocess",
        "threat_type": "RCE_COMMAND_INJECTION",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "patterns": [
            r"(?i)os\.system\s*\(",
            r"(?i)subprocess\.(Popen|call|run|check_output)\s*\(.*shell\s*=\s*True",
            r"(?i)os\.popen\s*\(",
            r"(?i)\beval\s*\(",
            r"(?i)\bexec\s*\("
        ],
        "description": "Dangerous execution of untrusted system commands or dynamic code evaluation.",
        "remediation": "Avoid invoking shell commands; use subprocess with a list of arguments (shell=False) and validate input strictly."
    },
    {
        "id": "SEC-004",
        "name": "Insecure Deserialization",
        "threat_type": "INSECURE_DESERIALIZATION",
        "severity": "HIGH",
        "cvss": 8.1,
        "patterns": [
            r"(?i)pickle\.loads\s*\(",
            r"(?i)_pickle\.loads\s*\(",
            r"(?i)yaml\.load\s*\([^,)]*\)", # yaml.load without Loader=SafeLoader
            r"(?i)marshal\.loads\s*\("
        ],
        "description": "Deserialization of untrusted data allows arbitrary Python object instantiation and code execution.",
        "remediation": "Use safe serializers like json.loads() or yaml.safe_load()."
    },
    {
        "id": "SEC-005",
        "name": "Weak Cryptographic Hash Algorithm",
        "threat_type": "WEAK_CRYPTO",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "patterns": [
            r"(?i)hashlib\.(md5|sha1)\s*\(",
            r"(?i)Crypto\.Cipher\.(DES|ARC4)\b",
            r"(?i)cryptography.*algorithms\.(MD5|SHA1)\("
        ],
        "description": "MD5 and SHA-1 have proven collision vulnerabilities and should never be used for password hashing or integrity guarantees.",
        "remediation": "Use Argon2id or bcrypt for password hashing; use SHA-256 or SHA-512 for data integrity."
    },
    {
        "id": "SEC-006",
        "name": "Dangerous Production Misconfiguration (Debug Mode / SSL Disabled)",
        "threat_type": "MISCONFIGURATION",
        "severity": "HIGH",
        "cvss": 7.5,
        "patterns": [
            r"(?i)app\.run\s*\(.*debug\s*=\s*True",
            r"(?i)DEBUG\s*=\s*True",
            r"(?i)verify\s*=\s*False", # requests verify=False
            r"(?i)CORS\s*\(.*['\"]\*['\"]"
        ],
        "description": "Application running with interactive debugger enabled or SSL verification disabled, exposing internal traces.",
        "remediation": "Disable debug mode in production (debug=False) and ensure SSL verification is enabled (verify=True)."
    }
]

class CodeAuditor:
    """Performs Static Application Security Testing on code snippets or repository files."""

    def audit_code_content(self, filename: str, code_content: str) -> Dict[str, Any]:
        """Inspect source code string and detect vulnerabilities."""
        lines = code_content.splitlines()
        findings = []
        
        for line_idx, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip empty lines or pure comments
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            for rule in CODE_VULN_RULES:
                for pattern in rule["patterns"]:
                    if re.search(pattern, line):
                        mitre = map_threat_to_mitre(rule["threat_type"])
                        findings.append({
                            "rule_id": rule["id"],
                            "vulnerability": rule["name"],
                            "threat_type": rule["threat_type"],
                            "severity": rule["severity"],
                            "cvss": rule["cvss"],
                            "file": filename,
                            "line_number": line_idx,
                            "code_snippet": stripped[:120],
                            "description": rule["description"],
                            "remediation": rule["remediation"],
                            "mitre": mitre
                        })
                        break  # Prevent duplicate hits for the same rule on the same line

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        overall_risk_score = 0
        if findings:
            highest_cvss = max(f["cvss"] for f in findings)
            overall_risk_score = round(min(10.0, highest_cvss + (len(findings) - 1) * 0.2), 1)

        return {
            "file": filename,
            "total_lines_analyzed": len(lines),
            "total_vulnerabilities": len(findings),
            "severity_breakdown": severity_counts,
            "risk_score": overall_risk_score,
            "findings": findings
        }

    def audit_file(self, file_path: str) -> Dict[str, Any]:
        """Audit a file on disk."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.audit_code_content(file_path, content)
        except Exception as e:
            return {
                "file": file_path,
                "error": str(e),
                "total_lines_analyzed": 0,
                "total_vulnerabilities": 0,
                "findings": []
            }
