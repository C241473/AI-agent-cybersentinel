# 🛡️ CyberSentinel AI — Autonomous SOC Operations Platform

CyberSentinel AI is an autonomous, multi-modal Cybersecurity Operations Center (SOC) agent and Threat Intelligence platform designed to inspect server logs, conduct static application security testing (SAST), audit network postures, query known CVE advisories, and formulate containment playbooks mapped to the **MITRE ATT&CK Enterprise Matrix**.

---

## ✨ Key Capabilities

1. 🤖 **Autonomous SOC Copilot (Chat)**
   - Conversational AI with dual-mode support: 100% offline knowledge base fallback + Gemini LLM integration.
   - Bilingual triage support (English & বাংলা).
   - Fast triage commands: `analyze log`, `audit code`, `scan host`, `cve <id>`, `generate report`.

2. 🔍 **Web & Auth Server Log Threat Analyzer**
   - Parses Apache, Nginx, Combined, and Custom access logs.
   - Detects SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal/LFI, Command Injection/RCE, Scanners (`sqlmap`, `nikto`, `gobuster`), and Brute Force attempts.
   - Auto-generates attacker IP threat scores and `iptables` / `ufw` drop rules with one-click copy.

3. 🛡️ **SAST Code Security Auditor**
   - Scans Python, JavaScript, and PHP files for OWASP Top 10 flaws, hardcoded credentials/tokens, dynamic query concatenations, and dangerous OS subprocess executions.
   - Provides CVSS v3.1 scoring, line-by-line vulnerability highlights, and precise remediation code.

4. 🌐 **Network Reconnaissance & HTTP Security Headers**
   - TCP port scanner for common high-risk exposed services (FTP, Telnet, MySQL, Redis, RDP, MongoDB).
   - Evaluates HTTP security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`) with grades.

5. ⚡ **Threat Intelligence & CVE Advisory System**
   - Offline & online intelligence database of high-impact vulnerabilities (e.g., Log4Shell, Spring4Shell, MOVEit, CitrixBleed).
   - Instant SOC containment playbooks, attack vector analysis, and affected software ranges.

6. 📋 **Automated Incident Report Generation**
   - Generates comprehensive markdown reports ready for export and download.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Flask Web Dashboard
```bash
python run.py
```
Then open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

### 3. Optional: Configure Gemini API Key
To enable generative deep reasoning via Gemini, create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(If no API key is provided, CyberSentinel AI runs 100% autonomously in offline SOC intelligence mode!)*

### 4. Deploy to Vercel
The Vercel deployment is protected with HTTP Basic Authentication. Before deploying, add
`CYBERSENTINEL_ACCESS_PASSWORD` as a Vercel environment variable for Production and Preview.
The login username is `cybersentinel`. If the password is missing, the app returns an error
instead of becoming publicly accessible. The Vercel deployment can be created with:
```bash
vercel --prod
```

---

## 📁 Project Architecture
```text
cybersentinel-ai/
├── agent/
│   ├── core.py             # Main SOC agent orchestrator & dispatch loop
│   ├── memory.py           # Conversational memory and incident store
│   └── prompts.py          # System prompts & report templates
├── tools/
│   ├── log_analyzer.py     # Log parser, regex signatures & IP scoring
│   ├── code_auditor.py     # SAST static analysis engine
│   ├── network_recon.py    # TCP port scanner & HTTP header auditor
│   ├── cve_advisory.py     # CVE threat intelligence repository
│   └── mitre_mapper.py     # MITRE ATT&CK tactic/technique mappings
├── samples/
│   ├── access.log          # Sample attack log for testing
│   └── vulnerable_app.py   # Intentional vulnerable Python app for SAST
├── templates/
│   └── index.html          # Modern Cyber SOC Web Dashboard
├── static/
│   ├── app.js              # Interactive client-side application logic
│   └── style.css           # Custom dark cyber glassmorphism styles
├── app.py                  # Flask application & REST endpoints
├── run.py                  # Application launcher
└── requirements.txt        # Python package dependencies
```
