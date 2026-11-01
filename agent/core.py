"""
CyberSentinel AI - Core Autonomous Security Reasoning Engine
Supports both Generative LLMs (Google Gemini 1.5 / 2.0 / OpenAI) and 
Dynamic Real-Time Autonomous Offline SOC Security Intelligence!
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests

from agent.prompts import SOC_AGENT_SYSTEM_PROMPT, REPORT_TEMPLATE
from agent.memory import SecurityMemory
from tools.log_analyzer import LogAnalyzer
from tools.code_auditor import CodeAuditor
from tools.network_recon import NetworkRecon
from tools.cve_advisory import CVEAdvisory
from tools.mitre_mapper import map_threat_to_mitre

class CyberSentinelAgent:
    """The central Autonomous Cybersecurity AI Agent."""

    def __init__(self, api_key: Optional[str] = None):
        self.memory = SecurityMemory()
        self.log_analyzer = LogAnalyzer()
        self.code_auditor = CodeAuditor()
        self.network_recon = NetworkRecon()
        self.cve_advisory = CVEAdvisory()
        self.public_demo = os.getenv("CYBERSENTINEL_PUBLIC_DEMO") == "1"

        # Check API key from argument, environment, or .env file
        self.gemini_key = (
            None
            if self.public_demo
            else api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or self._read_env_key()
        )
        self.openai_key = None if self.public_demo else os.getenv("OPENAI_API_KEY")
        
        # Tools registry for autonomous dispatch
        self.tools = {
            "analyze_log": self.analyze_log,
            "audit_code": self.audit_code,
            "lookup_cve": self.lookup_cve,
            "generate_report": self.generate_incident_report
        }
        if not self.public_demo:
            self.tools["scan_ports"] = self.scan_ports
            self.tools["inspect_headers"] = self.inspect_headers

    def _read_env_key(self) -> Optional[str]:
        """Read GEMINI_API_KEY from local .env file if exists."""
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("GEMINI_API_KEY="):
                            return line.split("=", 1)[1].strip().strip('"').strip("'")
            except Exception:
                pass
        return None

    def set_gemini_key(self, key: str) -> bool:
        """Update Gemini API Key in runtime and persist to .env."""
        key = key.strip()
        self.gemini_key = key
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        try:
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(f"GEMINI_API_KEY={key}\n")
            return True
        except Exception:
            return False

    # ==========================================
    # TOOL IMPLEMENTATIONS
    # ==========================================

    def analyze_log(self, file_path_or_text: str) -> Dict[str, Any]:
        """Analyze web server log file or raw log text."""
        if os.path.exists(file_path_or_text):
            result = self.log_analyzer.analyze_file(file_path_or_text)
            target = file_path_or_text
        else:
            result = self.log_analyzer.analyze_log_content(file_path_or_text)
            target = "Direct Log Stream"

        self.memory.record_scan_result("LOG_ANALYSIS", target, result)
        return result

    def audit_code(self, file_path_or_code: str, filename: str = "snippet.py") -> Dict[str, Any]:
        """Audit source code file or raw code snippet for vulnerabilities."""
        if os.path.exists(file_path_or_code):
            result = self.code_auditor.audit_file(file_path_or_code)
            target = file_path_or_code
        else:
            result = self.code_auditor.audit_code_content(filename, file_path_or_code)
            target = filename

        self.memory.record_scan_result("CODE_AUDIT", target, result)
        return result

    def scan_ports(self, host: str) -> Dict[str, Any]:
        """Perform TCP reconnaissance scan against target host."""
        if self.public_demo:
            return {"host": host, "error": "Network reconnaissance is disabled in the public demo.", "open_ports": []}
        result = self.network_recon.scan_ports(host)
        self.memory.record_scan_result("PORT_SCAN", host, result)
        return result

    def inspect_headers(self, url: str) -> Dict[str, Any]:
        """Inspect HTTP security headers for a target website."""
        if self.public_demo:
            return {"target_url": url, "error": "Network reconnaissance is disabled in the public demo."}
        result = self.network_recon.inspect_web_headers(url)
        self.memory.record_scan_result("HEADER_INSPECTION", url, result)
        return result

    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """Query Threat Intelligence database for CVE details and mitigation."""
        return self.cve_advisory.lookup(cve_id)

    # ==========================================
    # UNIVERSAL INPUT DETECTOR
    # ==========================================

    def detect_input_type(self, text: str) -> str:
        """
        Automatically classifies ANY user text into:
        - 'SET_KEY' : API key configuration
        - 'LOG'     : Web/Auth server log stream
        - 'CODE'    : Source code snippet
        - 'CVE'     : Specific CVE identifier
        - 'IP'      : Standalone IP address
        - 'URL'     : Web URL or domain
        - 'REPORT'  : Report generation
        - 'QUERY'   : General cybersecurity inquiry
        """
        trimmed = text.strip()
        lower = trimmed.lower()

        # Check for API Key setting
        if any(w in lower for w in ["set key", "set api key", "gemini key", "api_key="]):
            return "SET_KEY"

        # Check for Report
        if any(w in lower for w in ["generate report", "incident report", "make report", "download report", "report banao"]):
            return "REPORT"

        # Check for CVE ID
        if re.search(r"\b(CVE-\d{4}-\d{4,7})\b", trimmed, re.IGNORECASE):
            return "CVE"

        # Check for explicit log commands or raw log format
        if "analyze log" in lower or "scan log" in lower:
            return "LOG"
        if re.search(r'["\'](GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\S+', trimmed):
            return "LOG"
        if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b.*\[\d{1,2}/\w{3}/\d{4}', trimmed):
            return "LOG"

        # Check for explicit code commands or raw code syntax
        if "audit code" in lower or "scan code" in lower or "check code" in lower:
            return "CODE"
        code_markers = [
            "def ", "class ", "import ", "function(", "function ", "SELECT ", "INSERT INTO",
            "UPDATE ", "DELETE FROM", "cursor.execute", "subprocess.", "os.system",
            "<?php", "console.log", "const ", "let ", "var ", "#!/bin/", "eval(", "exec("
        ]
        if any(m in trimmed for m in code_markers):
            return "CODE"

        # Check for single IP address
        if re.fullmatch(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', trimmed):
            return "IP"

        # Check for URL
        if re.fullmatch(r'https?://\S+|www\.\S+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', trimmed):
            return "URL"

        return "QUERY"

    # ==========================================
    # AGENT REASONING & DISPATCH LOOP
    # ==========================================

    def chat(self, user_prompt: str) -> str:
        """Process user input dynamically, run tools, or leverage Gemini/SOC intelligence."""
        self.memory.add_message("user", user_prompt)
        input_type = self.detect_input_type(user_prompt)

        if self.public_demo and (
            input_type in {"IP", "URL"}
            or re.search(r"\b(scan\s+(host|ip)|audit\s+headers?|check\s+headers?)\b", user_prompt, re.IGNORECASE)
        ):
            response = "Network reconnaissance is disabled in this public demo. You can still analyze logs, audit code, and look up CVEs."
            self.memory.add_message("assistant", response)
            return response

        # 1. API Key Setup
        if input_type == "SET_KEY":
            key_match = re.search(r'(?:key\s*[:=]?\s*|gemini_key\s*[:=]?\s*)(AIza[0-9A-Za-z-_]{30,}|[0-9A-Za-z-_]{30,})', user_prompt, re.IGNORECASE)
            if key_match:
                key = key_match.group(1).strip()
                if self.set_gemini_key(key):
                    resp = (
                        "🎉 **Gemini AI Connection Established!**\n\n"
                        f"✅ Your Google Gemini API Key has been saved to `.env`.\n"
                        "CyberSentinel is now augmented with **Gemini Generative Intelligence** for deep multi-modal reasoning! "
                        "You can now ask complex cybersecurity questions, paste arbitrary scripts, or request architecture advice."
                    )
                    self.memory.add_message("assistant", resp)
                    return resp
            return "⚠️ Please provide a valid Gemini API key (e.g., `set key AIzaSy...`). You can obtain a free key at [Google AI Studio](https://aistudio.google.com/)."

        # 2. Incident Report Request
        if input_type == "REPORT":
            response = self.generate_incident_report()
            self.memory.add_message("assistant", response)
            return response

        # 3. Log Analysis (File Path or Raw Log Stream)
        if input_type == "LOG":
            file_match = re.search(r"(\S+\.log)", user_prompt)
            if file_match and os.path.exists(file_match.group(1)):
                res = self.analyze_log(file_match.group(1))
                target = file_match.group(1)
            else:
                # Raw log text directly provided
                clean_log = re.sub(r'^(analyze\s+log|scan\s+log)\s*', '', user_prompt, flags=re.IGNORECASE).strip()
                res = self.analyze_log(clean_log)
                target = "User Injected Log Stream"

            response = self._synthesize_log_analysis(res, target)
            self.memory.add_message("assistant", response)
            return response

        # 4. SAST Code Audit (File Path or Raw Code Snippet)
        if input_type == "CODE":
            file_match = re.search(r"(\S+\.(py|js|php|json|yml|yaml))", user_prompt)
            if file_match and os.path.exists(file_match.group(1)):
                res = self.audit_code(file_match.group(1))
                target = file_match.group(1)
            else:
                clean_code = re.sub(r'^(audit\s+code|scan\s+code|check\s+code)\s*', '', user_prompt, flags=re.IGNORECASE).strip()
                res = self.audit_code(clean_code, filename="custom_snippet.py")
                target = "custom_snippet.py"

            response = self._synthesize_code_audit(res, target)
            self.memory.add_message("assistant", response)
            return response

        # 5. Standalone Host IP Recon
        if input_type == "IP" or ("scan host" in user_prompt.lower() or "scan ip" in user_prompt.lower()):
            host_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", user_prompt)
            if host_match:
                host = host_match.group(0)
                res = self.scan_ports(host)
                response = self._synthesize_port_scan(res)
                self.memory.add_message("assistant", response)
                return response

        # 6. Web Security Header Audit
        if input_type == "URL" or ("audit header" in user_prompt.lower() or "check header" in user_prompt.lower()):
            url_match = re.search(r"https?://\S+|www\.\S+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", user_prompt)
            if url_match:
                url = url_match.group(0)
                res = self.inspect_headers(url)
                response = self._synthesize_headers(res)
                self.memory.add_message("assistant", response)
                return response

        # 7. Specific CVE Lookup
        if input_type == "CVE":
            cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", user_prompt, re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(1).upper()
                res = self.lookup_cve(cve_id)
                response = self._synthesize_cve(res, cve_id)
                self.memory.add_message("assistant", response)
                return response

        # 8. If Gemini Key is present, dispatch to Gemini API
        if self.gemini_key:
            gemini_resp = self._call_gemini_api(user_prompt)
            if gemini_resp:
                self.memory.add_message("assistant", gemini_resp)
                return gemini_resp

        # 9. Dynamic Autonomous SOC Intelligence Knowledge Engine (100% Offline)
        response = self._dynamic_soc_intelligence(user_prompt)
        self.memory.add_message("assistant", response)
        return response

    # ==========================================
    # GEMINI AI DISPATCH ENGINE
    # ==========================================

    def _call_gemini_api(self, prompt: str) -> Optional[str]:
        """Dispatch query to Google Gemini Models with fallback."""
        models = ["gemini-1.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]
        headers = {"Content-Type": "application/json"}
        
        # Build conversational history
        contents = []
        for m in self.memory.messages[-6:]:
            role = "user" if m["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m["content"]}]})

        # Add current prompt with system context
        contents.append({
            "role": "user",
            "parts": [{"text": f"{SOC_AGENT_SYSTEM_PROMPT}\n\nUser Question:\n{prompt}"}]
        })

        for model in models:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.gemini_key}"
                payload = {"contents": contents}
                resp = requests.post(url, headers=headers, json=payload, timeout=14)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts:
                            return parts[0]["text"]
            except Exception:
                continue
        return None

    # ==========================================
    # UNIVERSAL DEEP INSPECTION DISPATCH
    # ==========================================

    def universal_inspect(self, input_text: str) -> Dict[str, Any]:
        """Takes ANY arbitrary user input, auto-detects its type, and returns structured findings."""
        category = self.detect_input_type(input_text)
        
        if category == "LOG":
            res = self.log_analyzer.analyze_log_content(input_text)
            synthesis = self._synthesize_log_analysis(res, "Universal Log Inspector")
            return {
                "category": "LOG_ANALYSIS",
                "badge": "SERVER_LOG_STREAM",
                "result": res,
                "synthesis": synthesis,
                "risk_score": 9.5 if res["summary"]["severity_breakdown"]["CRITICAL"] > 0 else (7.0 if res["summary"]["total_threats_detected"] > 0 else 1.0)
            }

        elif category == "CODE":
            res = self.code_auditor.audit_code_content("inspected_code.py", input_text)
            synthesis = self._synthesize_code_audit(res, "inspected_code.py")
            return {
                "category": "CODE_AUDIT",
                "badge": "SOURCE_CODE_SAST",
                "result": res,
                "synthesis": synthesis,
                "risk_score": res.get("risk_score", 0.0)
            }

        elif category == "IP":
            if self.public_demo:
                return {
                    "category": "NETWORK_RECON_DISABLED",
                    "badge": "PUBLIC_DEMO_LIMIT",
                    "result": {"error": "Network reconnaissance is disabled in the public demo."},
                    "synthesis": "Network reconnaissance is disabled in this public demo. You can still analyze logs, audit code, and look up CVEs.",
                    "risk_score": 0.0
                }
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', input_text)
            ip = ip_match.group(0) if ip_match else input_text.strip()
            res = self.scan_ports(ip)
            synthesis = self._synthesize_port_scan(res)
            return {
                "category": "NETWORK_RECON",
                "badge": "TCP_PORT_SCAN",
                "result": res,
                "synthesis": synthesis,
                "risk_score": 8.0 if len(res.get("open_ports", [])) > 2 else 2.5
            }

        elif category == "URL":
            if self.public_demo:
                return {
                    "category": "NETWORK_RECON_DISABLED",
                    "badge": "PUBLIC_DEMO_LIMIT",
                    "result": {"error": "Network reconnaissance is disabled in the public demo."},
                    "synthesis": "Network reconnaissance is disabled in this public demo. You can still analyze logs, audit code, and look up CVEs.",
                    "risk_score": 0.0
                }
            url_match = re.search(r'https?://\S+|www\.\S+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', input_text)
            url = url_match.group(0) if url_match else input_text.strip()
            res = self.inspect_headers(url)
            synthesis = self._synthesize_headers(res)
            return {
                "category": "HEADER_AUDIT",
                "badge": "HTTP_SECURITY_HEADERS",
                "result": res,
                "synthesis": synthesis,
                "risk_score": 8.5 if res.get("security_grade") in ['F', 'D'] else 3.0
            }

        elif category == "CVE":
            cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", input_text, re.IGNORECASE)
            cve_id = cve_match.group(1).upper() if cve_match else "CVE-2021-44228"
            res = self.lookup_cve(cve_id)
            synthesis = self._synthesize_cve(res, cve_id)
            return {
                "category": "CVE_INTEL",
                "badge": "THREAT_INTELLIGENCE",
                "result": res,
                "synthesis": synthesis,
                "risk_score": res.get("cvss_score", 9.0)
            }

        else:
            answer = self._dynamic_soc_intelligence(input_text)
            return {
                "category": "SECURITY_CONSULTATION",
                "badge": "SOC_INTELLIGENCE",
                "result": {"query": input_text},
                "synthesis": answer,
                "risk_score": 5.0
            }

    # ==========================================
    # DYNAMIC OFFLINE SOC INTELLIGENCE ENGINE
    # ==========================================

    def _dynamic_soc_intelligence(self, prompt: str) -> str:
        """Comprehensive offline cyber intelligence engine covering key attack vectors."""
        p = prompt.lower()

        # Greetings
        if any(w in p for w in ["hi", "hello", "hey", "salam", "greetings", "who are you", "what can you do"]):
            return (
                "👋 **Greetings, Commander. I am CyberSentinel AI — your Autonomous Tier-3 SOC Security Agent.**\n\n"
                "I am operational and ready to secure your infrastructure, web applications, and source code repositories. "
                "You can inspect **any telemetry or data** directly:\n\n"
                "- 📜 **Server Access Logs:** Paste one or more raw log lines — I will identify SQLi, XSS, Path Traversal, and generate firewall drop rules.\n"
                "- 💻 **Source Code Audits:** Paste Python, JavaScript, or PHP snippets — I will detect hardcoded secrets, injection flaws, and provide secure remediation code.\n"
                "- 🌐 **Host / IP / URL Recon:** Input any IP or domain — I will scan exposed service ports and evaluate HTTP security headers.\n"
                "- ⚡ **CVE Intelligence:** Query any known vulnerability (e.g. `CVE-2021-44228`) — I will provide CVSS metrics, affected versions, and mitigation playbooks.\n"
                "- 🔑 **Connect Gemini AI:** To enable generative deep multi-modal reasoning, enter: `set key <YOUR_GEMINI_API_KEY>` or click the top header button.\n\n"
                "*(Try testing: `cursor.execute(f\"SELECT * FROM users WHERE id = '{id}'\")`)*"
            )

        # SQL Injection
        if any(w in p for w in ["sql", "sqli", "database hack", "sql injection"]):
            return (
                "### 🛡️ CyberSentinel Advisory: SQL Injection (SQLi)\n\n"
                "**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)\n"
                "**Severity:** CRITICAL (CVSS 9.8)\n\n"
                "**Overview:**\n"
                "SQL Injection occurs when untrusted user input is directly concatenated into dynamic SQL queries, allowing remote adversaries to manipulate database queries, bypass authentication, exfiltrate confidential tables, or drop databases.\n\n"
                "**Common Attack Signatures:**\n"
                "- `' OR 1=1 --`\n"
                "- `' UNION SELECT null, username, password FROM users --`\n"
                "- `1; WAITFOR DELAY '0:0:10'--` (Time-based Blind Injection)\n\n"
                "**Remediation & Secure Code Pattern:**\n"
                "```python\n"
                "# INSECURE DYNAMIC CONCATENATION:\n"
                "# cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n\n"
                "# SECURE PARAMETERIZED QUERY (Prepared Statement):\n"
                "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "```\n"
                "> 💡 **SOC Guidance:** Enforce parameterized queries across all database drivers, utilize an ORM, and activate Web Application Firewall (WAF) SQLi inspection rules."
            )

        # XSS
        if any(w in p for w in ["xss", "cross site", "cross-site scripting", "javascript injection"]):
            return (
                "### 🛡️ CyberSentinel Advisory: Cross-Site Scripting (XSS)\n\n"
                "**MITRE ATT&CK:** T1189 (Drive-by Compromise) / T1059.007 (JavaScript Execution)\n"
                "**Severity:** HIGH (CVSS 7.5 - 8.8)\n\n"
                "**Overview:**\n"
                "Cross-Site Scripting allows an adversary to execute arbitrary client-side JavaScript in a victim's browser to hijack active session cookies, redirect users to phishing portals, or perform unauthorized DOM actions on behalf of the victim.\n\n"
                "**Remediation Steps:**\n"
                "1. **Context-Aware Output Encoding:** Escape all HTML special entities (e.g., convert `<script>` to `&lt;script&gt;`).\n"
                "2. **Content-Security-Policy (CSP):** Enforce strict directives: `Content-Security-Policy: default-src 'self'; script-src 'self';`\n"
                "3. **HttpOnly Cookie Flags:** Set `HttpOnly; Secure; SameSite=Strict` on sensitive session cookies to prevent client-side JavaScript access."
            )

        # Brute Force / DDoS
        if any(w in p for w in ["brute force", "ddos", "dos", "rate limit", "bot attack", "credential stuffing"]):
            return (
                "### 🛡️ CyberSentinel Advisory: Brute Force & Denial of Service (DoS/DDoS) Defense\n\n"
                "**MITRE ATT&CK:** T1110 (Brute Force / Credential Stuffing) / T1499 (Endpoint DoS)\n"
                "**Severity:** HIGH (CVSS 7.5)\n\n"
                "**Immediate Mitigation Playbook:**\n"
                "1. **Rate Limiting:** Enforce strict thresholds at edge proxies (e.g., maximum 5 login attempts per minute per source IP).\n"
                "2. **Automated Firewall Containment (Fail2Ban / iptables):**\n"
                "   ```bash\n"
                "   iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT\n"
                "   ```\n"
                "3. **Multi-Factor Authentication (MFA):** Enforce mandatory FIDO2 / TOTP multi-factor authentication across all authentication endpoints."
            )

        # Phishing
        if any(w in p for w in ["phishing", "credential harvesting", "social engineering", "spear phishing"]):
            return (
                "### 🛡️ CyberSentinel Advisory: Phishing & Credential Theft Mitigation\n\n"
                "**MITRE ATT&CK:** T1566 (Phishing)\n"
                "**Severity:** HIGH (CVSS 8.1)\n\n"
                "**Containment & Defense Controls:**\n"
                "1. **Email DNS Hardening:** Deploy SPF, DKIM, and strict DMARC rejection policy (`v=DMARC1; p=reject;`).\n"
                "2. **FIDO2 / WebAuthn Hardware Security:** Implement phishing-resistant Passkeys or YubiKey hardware tokens to prevent credential harvesting.\n"
                "3. **Inbound Link Inspection:** Enforce real-time URL sandboxing and credential-entry protection on corporate mail gateways."
            )

        # Ransomware / Malware / RCE
        if any(w in p for w in ["ransomware", "malware", "virus", "trojan", "rce", "remote code", "command injection"]):
            return (
                "### 🛡️ CyberSentinel Advisory: Ransomware & Remote Code Execution (RCE)\n\n"
                "**MITRE ATT&CK:** T1486 (Data Encrypted for Impact) / T1059 (Command Interpreter)\n"
                "**Severity:** CRITICAL (CVSS 9.8)\n\n"
                "**Emergency Incident Response Playbook:**\n"
                "1. **Immediate Host Isolation:** Disconnect the compromised endpoint from internal network segments and WAN (`ifconfig eth0 down` or isolate via EDR agent).\n"
                "2. **Process Triage:** Inspect high-utilization or unsigned background processes (`ps aux --sort=-%cpu`) and terminate suspicious PIDs immediately (`kill -9 <PID>`).\n"
                "3. **Immutable Backups:** Ensure offline 3-2-1 backup rotation is maintained and test restoration procedures."
            )

        # Fallback Analysis Prompt
        return (
            f"🔍 **CyberSentinel Deep Analysis:**\n\n"
            f"Input Received: *\"{prompt}\"*\n\n"
            "CyberSentinel is primed to analyze and triage any cybersecurity input:\n\n"
            "1. 📜 **Server Logs:** Paste raw Apache or Nginx access lines — I will extract threat vectors and compile firewall drop commands.\n"
            "2. 💻 **Source Code:** Paste code snippets — I will locate vulnerabilities, CVSS scores, and provide remediations.\n"
            "3. 🌐 **Host / Domain:** Enter an IP or URL — I will scan common service ports and audit HTTP headers.\n"
            "4. ⚡ **Connect Gemini AI:** Enter your key via `set key <YOUR_KEY>` or click the **Connect Gemini AI** button in the header.\n\n"
            "> 💡 **Tip:** Use the **Universal Inspector** tab on the left for one-click automatic classification and deep audit."
        )

    # ==========================================
    # SYNTHESIS GENERATORS (SOC FORMATTED)
    # ==========================================

    def _synthesize_log_analysis(self, result: Dict[str, Any], target: str) -> str:
        summary = result.get("summary", {})
        alerts = result.get("alerts", [])
        attackers = result.get("top_attacker_ips", [])

        crit = summary.get("severity_breakdown", {}).get("CRITICAL", 0)
        high = summary.get("severity_breakdown", {}).get("HIGH", 0)
        
        status_banner = "🔴 CRITICAL THREAT DETECTED" if crit > 0 else ("🟠 HIGH RISK DETECTED" if high > 0 else "🟢 LOW / NORMAL ACTIVITY")

        lines = [
            f"### {status_banner}",
            f"**Target Analyzed:** `{target}`",
            f"- **Total Requests Processed:** {summary.get('total_requests', 0)} from {summary.get('unique_ips', 0)} unique IP(s)",
            f"- **Security Incidents Flagged:** {summary.get('total_threats_detected', 0)}",
            f"- **Severity Breakdown:** Critical: {crit} | High: {high} | Medium: {summary.get('severity_breakdown', {}).get('MEDIUM', 0)} | Low: {summary.get('severity_breakdown', {}).get('LOW', 0)}",
            "\n#### 🚨 Detected Attack Signatures & MITRE ATT&CK:"
        ]

        seen_types = set()
        for alert in alerts:
            t = alert["threat_type"]
            if t not in seen_types:
                seen_types.add(t)
                mitre = alert.get("mitre", {})
                lines.append(f"- **{t}** [{alert['severity']}] -> **MITRE {mitre.get('technique_id')} ({mitre.get('technique_name')})**: {alert['description']}")

        if attackers:
            lines.append("\n#### 🎯 Identified Attacker IPs & Automated Firewall Actions:")
            for att in attackers[:5]:
                lines.append(f"- **IP:** `{att['ip']}` | **Threat Score:** {att['threat_score']}/100 | **Attacks:** {', '.join(att['threat_types'])}")
                lines.append(f"  * Recommended Drop Command: `{att['recommended_action']}`")

        lines.append("\n> 💡 **SOC Containment Action:** Apply the suggested firewall drop rules immediately in your edge router or cloud security group.")
        return "\n".join(lines)

    def _synthesize_code_audit(self, result: Dict[str, Any], target: str) -> str:
        findings = result.get("findings", [])
        risk_score = result.get("risk_score", 0.0)
        
        lines = [
            f"### 🛡️ SAST Security Audit: `{target}`",
            f"- **Analyzed Lines:** {result.get('total_lines_analyzed', 0)}",
            f"- **Vulnerabilities Identified:** {len(findings)}",
            f"- **Aggregate Risk Score:** {risk_score}/10.0\n"
        ]

        if not findings:
            lines.append("✅ **No critical security flaws or hardcoded secrets detected!**")
            return "\n".join(lines)

        lines.append("#### ⚠️ Detailed Vulnerability Findings:")
        for idx, f in enumerate(findings[:8], 1):
            lines.append(f"{idx}. **[{f['severity']}] {f['vulnerability']}** (CVSS {f['cvss']})")
            lines.append(f"   - **Line {f['line_number']}:** `{f['code_snippet']}`")
            lines.append(f"   - **MITRE TTP:** {f['mitre']['technique_id']} - {f['mitre']['technique_name']}")
            lines.append(f"   - **Remediation:** {f['remediation']}")

        lines.append("\n> 🔒 **Action Item:** Remediate the hardcoded credentials and dynamic SQL/subprocess invocations before pushing code to production.")
        return "\n".join(lines)

    def _synthesize_port_scan(self, result: Dict[str, Any]) -> str:
        host = result.get("target_host")
        ip = result.get("target_ip")
        open_ports = result.get("open_ports", [])

        lines = [
            f"### 🌐 Network Reconnaissance: `{host}` ({ip})",
            f"- **Scanned Common Ports:** {result.get('scanned_ports_count', 0)}",
            f"- **Exposed / Open Ports:** {len(open_ports)}\n"
        ]

        if not open_ports:
            lines.append("🛡️ **All tested ports appear filtered or closed.** Host does not expose standard insecure services.")
            return "\n".join(lines)

        lines.append("| Port | Service | Risk Level | SOC Guidance |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for p in open_ports:
            lines.append(f"| **{p['port']}** | {p['service']} | **{p['risk']}** | {p['security_note']} |")

        return "\n".join(lines)

    def _synthesize_headers(self, result: Dict[str, Any]) -> str:
        url = result.get("target_url")
        grade = result.get("security_grade")
        findings = result.get("findings", [])

        lines = [
            f"### 🔒 HTTP Security Headers Audit: `{url}`",
            f"- **Security Grade:** **{grade}**",
            f"- **Assessed Headers:** {len(findings)}\n",
            "| Header | Status | Recommended Standard |",
            "| :--- | :--- | :--- |"
        ]

        for f in findings:
            status_emoji = "✅ PASS" if f["status"] == "PASS" else "❌ FAIL"
            lines.append(f"| `{f['header']}` | {status_emoji} | `{f['recommended_value']}` |")

        return "\n".join(lines)

    def _synthesize_cve(self, result: Dict[str, Any], cve_id: str) -> str:
        lines = [
            f"### ⚡ Threat Advisory: `{cve_id}` — {result.get('name', 'Known Vulnerability')}",
            f"- **Severity:** **{result.get('severity', 'HIGH')}** (CVSS: {result.get('cvss_score', 'N/A')}/10.0)",
            f"- **Attack Vector:** {result.get('attack_vector', 'Network')}",
            f"- **Affected Software:** `{result.get('affected_software', 'Unknown')}`",
            f"- **MITRE Technique:** `{result.get('mitre_technique', 'T1190')}`\n",
            f"**Description:**\n{result.get('description', 'No description available.')}\n",
            "#### 🛡️ Containment Playbook & Mitigation:"
        ]
        for step in result.get("mitigation_steps", []):
            lines.append(f"- {step}")

        return "\n".join(lines)

    def generate_incident_report(self) -> str:
        """Synthesize multi-modal scan telemetry into an executive incident report."""
        last_scan = self.memory.get_last_scan()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        if not last_scan:
            return REPORT_TEMPLATE.format(
                timestamp=now_str,
                target="General Environment Assessment",
                posture_rating="NOMINAL",
                risk_score=1.5,
                executive_summary="No active threat scans or security audits have been loaded yet in this session. Run log triage, code audit, or network recon to populate an incident report.",
                findings_table="| ID | Type | Severity | Status |\n|---|---|---|---|\n| N/A | None | Low | Monitored |",
                mitre_mapping="- No active TTPs flagged.",
                containment_commands="# No containment actions required.",
                remediation_steps="1. Conduct periodic vulnerability scans.\n2. Ensure logging is enabled across all edge proxies."
            )

        scan_type = last_scan.get("scan_type")
        target = last_scan.get("target")
        data = last_scan.get("result", {})

        if scan_type == "LOG_ANALYSIS":
            summary = data.get("summary", {})
            total_threats = summary.get("total_threats_detected", 0)
            crit = summary.get("severity_breakdown", {}).get("CRITICAL", 0)
            risk = 9.5 if crit > 0 else (7.2 if total_threats > 0 else 2.0)
            rating = "CRITICAL COMPROMISE RISK" if crit > 0 else ("SUSPICIOUS ACTIVITY" if total_threats > 0 else "SECURE")

            findings_rows = []
            for alert in data.get("alerts", [])[:10]:
                findings_rows.append(f"| {alert.get('threat_type')} | {alert.get('severity')} | {alert.get('ip')} | {alert.get('uri')[:30]} |")
            findings_table = "| Attack Type | Severity | Source IP | Target URI |\n| :--- | :--- | :--- | :--- |\n" + "\n".join(findings_rows)

            containment = "\n".join([a["recommended_action"] for a in data.get("top_attacker_ips", [])]) or "# No malicious IPs identified."

            mitre_list = []
            for a in data.get("alerts", [])[:5]:
                m = a.get("mitre", {})
                mitre_list.append(f"- **{m.get('technique_id')} ({m.get('technique_name')})**: {m.get('description')}")
            mitre_str = "\n".join(set(mitre_list)) or "No mapped techniques."

            return REPORT_TEMPLATE.format(
                timestamp=now_str,
                target=target,
                posture_rating=rating,
                risk_score=risk,
                executive_summary=f"Analysis of server log `{target}` detected {total_threats} security threats across {summary.get('unique_ips', 0)} interacting hosts.",
                findings_table=findings_table,
                mitre_mapping=mitre_str,
                containment_commands=containment,
                remediation_steps="1. Deploy automated IP blocking using Fail2Ban or cloud WAF.\n2. Patch exposed endpoints identified in the attack paths.\n3. Sanitize inputs and enforce parameterized queries."
            )

        elif scan_type == "CODE_AUDIT":
            findings = data.get("findings", [])
            risk = data.get("risk_score", 0.0)
            rating = "HIGH VULNERABILITY EXPOSURE" if risk >= 7.0 else ("MODERATE RISK" if risk > 4.0 else "SECURE")

            findings_rows = []
            for f in findings:
                findings_rows.append(f"| {f.get('rule_id')} | {f.get('vulnerability')} | {f.get('severity')} | Line {f.get('line_number')} |")
            findings_table = "| Rule ID | Vulnerability | Severity | Location |\n| :--- | :--- | :--- | :--- |\n" + "\n".join(findings_rows)

            containment = "# 1. Immediately revoke and rotate any leaked credentials/API keys\n# 2. Halt CI/CD release pipeline until critical findings are resolved"
            mitre_str = "\n".join([f"- **{f['mitre']['technique_id']} ({f['mitre']['technique_name']})**: {f['description']}" for f in findings[:5]])

            return REPORT_TEMPLATE.format(
                timestamp=now_str,
                target=target,
                posture_rating=rating,
                risk_score=risk,
                executive_summary=f"Static code security analysis of `{target}` identified {len(findings)} vulnerability findings with an aggregate risk score of {risk}/10.0.",
                findings_table=findings_table or "| None | Clean Code | PASS | None |",
                mitre_mapping=mitre_str or "No TTPs discovered.",
                containment_commands=containment,
                remediation_steps="1. Refactor SQL queries into parameterized statements.\n2. Move hardcoded API tokens into environment variables.\n3. Use bandit/semgrep in automated pre-commit git hooks."
            )

        return f"Incident report generated for {scan_type} on {target}."
