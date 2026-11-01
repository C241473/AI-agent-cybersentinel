"""
MITRE ATT&CK Matrix Mapping Module for CyberSentinel AI.
Maps detected security alerts to Tactics, Techniques, and Procedures (TTPs).
"""

MITRE_TECHNIQUES = {
    "SQL_INJECTION": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique": None,
        "description": "Adversary exploits SQL query execution flaw in public web application to bypass authentication or extract database records.",
        "mitigation": "Use parameterized queries (prepared statements), ORM, input validation, and WAF rules."
    },
    "XSS": {
        "tactic": "Initial Access / Execution",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "subtechnique": "T1059.007",
        "description": "Adversary injects malicious JavaScript into web content delivered to victim browsers to hijack sessions.",
        "mitigation": "Context-aware output encoding, Content Security Policy (CSP), and HttpOnly cookie flags."
    },
    "PATH_TRAVERSAL": {
        "tactic": "Discovery / Credential Access",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "subtechnique": "T1005",
        "description": "Adversary manipulates file path parameters (e.g., ../) to access restricted server files like /etc/passwd or win.ini.",
        "mitigation": "Sanitize user path inputs with chroot jail, whitelist filenames, and avoid direct filesystem concatenation."
    },
    "BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "subtechnique": "T1110.001",
        "description": "Adversary repeatedly guesses passwords or auth tokens using automated credential stuffing or wordlists.",
        "mitigation": "Enforce account lockouts, rate limiting, Multi-Factor Authentication (MFA), and CAPTCHA."
    },
    "RCE_COMMAND_INJECTION": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "subtechnique": "T1059.004",
        "description": "Adversary executes unauthorized operating system commands via web request parameters or untrusted inputs.",
        "mitigation": "Never pass user input directly into system shells (system, exec, Popen with shell=True). Restrict permissions."
    },
    "RECON_SCANNER": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "subtechnique": "T1595.002",
        "description": "Adversary runs automated security scanners (e.g. sqlmap, nikto, nmap, gobuster) to probe vulnerabilities.",
        "mitigation": "Block known malicious User-Agents, implement rate-limiting, and deploy Web Application Firewalls."
    },
    "SENSITIVE_FILE_PROBING": {
        "tactic": "Discovery",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "subtechnique": "T1552.001",
        "description": "Adversary probes web root for exposed secrets, .git repositories, .env files, backup databases, or private keys.",
        "mitigation": "Disable web directory indexing, forbid access to hidden dotfiles (.git, .env) in Nginx/Apache configuration."
    },
    "HARDCODED_SECRET": {
        "tactic": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Credentials in Files",
        "subtechnique": "T1552.001",
        "description": "Developers hardcoded API keys, JWT secrets, or DB credentials directly into application source code.",
        "mitigation": "Rotate exposed credentials immediately; use secrets managers (HashiCorp Vault, AWS Secrets Manager, .env outside VCS)."
    },
    "INSECURE_DESERIALIZATION": {
        "tactic": "Execution",
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "subtechnique": None,
        "description": "Untrusted serialized data (e.g., pickle, Java serialized objects) executed by backend leading to remote code execution.",
        "mitigation": "Use safe data serialization formats such as JSON; avoid pickle/marshal with untrusted data."
    },
    "WEAK_CRYPTO": {
        "tactic": "Defense Evasion / Credential Access",
        "technique_id": "T1600",
        "technique_name": "Weaken Encryption",
        "subtechnique": "T1600.002",
        "description": "Use of cryptographically broken algorithms (MD5, SHA-1, DES) enabling collision and fast hash cracking.",
        "mitigation": "Upgrade to Argon2id, bcrypt, or PBKDF2 for passwords; use AES-GCM or ChaCha20-Poly1305 for data encryption."
    }
}

def map_threat_to_mitre(threat_type: str) -> dict:
    """Return MITRE ATT&CK information for a given threat type."""
    key = threat_type.upper().strip()
    if key in MITRE_TECHNIQUES:
        return MITRE_TECHNIQUES[key]
    
    # Fuzzy match
    for k, data in MITRE_TECHNIQUES.items():
        if k in key or key in k:
            return data
            
    return {
        "tactic": "Uncategorized",
        "technique_id": "T1000",
        "technique_name": "General Adversary Technique",
        "subtechnique": None,
        "description": "Detected anomalous activity requiring manual SOC analyst triage.",
        "mitigation": "Review logs and monitor host activity."
    }
