"""
CyberSentinel AI - Web Application Backend (Flask)
Autonomous Cybersecurity SOC Operations Center
"""

import os
import sys
import hmac
from datetime import datetime
from typing import Dict, Any
from flask import Flask, Response, render_template, request, jsonify, send_file
import io

# Ensure project directory is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from agent.core import CyberSentinelAgent

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload


@app.before_request
def require_vercel_password():
    if os.environ.get("VERCEL") != "1":
        return None

    expected_password = os.environ.get("CYBERSENTINEL_ACCESS_PASSWORD")
    if not expected_password:
        return jsonify({"error": "Vercel access password is not configured"}), 503

    authorization = request.authorization
    supplied_password = (authorization.password or "") if authorization else ""
    if (
        authorization
        and authorization.username == "cybersentinel"
        and hmac.compare_digest(supplied_password, expected_password)
    ):
        return None

    return Response(
        "Authentication required",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="CyberSentinel", charset="UTF-8"'},
    )


# Initialize SOC Agent Instance
agent = CyberSentinelAgent()

@app.route("/")
def index():
    """Render the main SOC Operations Dashboard."""
    return render_template("index.html")

@app.route("/api/status", methods=["GET"])
def api_status():
    """System health and agent readiness."""
    last_scan = agent.memory.get_last_scan()
    return jsonify({
        "status": "online",
        "agent": "CyberSentinel AI SOC Agent",
        "has_gemini_key": bool(agent.gemini_key),
        "mode": "Gemini AI Active" if agent.gemini_key else "Autonomous SOC Mode",
        "memory_messages": len(agent.memory.messages),
        "total_scans_logged": len(agent.memory.past_scans),
        "last_scan_type": last_scan.get("scan_type") if last_scan else None,
        "last_scan_target": last_scan.get("target") if last_scan else None,
        "timestamp": datetime.now().isoformat()
    })

@app.route("/api/settings/gemini-key", methods=["POST"])
def api_set_gemini_key():
    """Save and activate user Gemini API key."""
    data = request.get_json(silent=True) or {}
    key = data.get("api_key", "").strip()
    if not key:
        return jsonify({"error": "API Key is required"}), 400
    if agent.set_gemini_key(key):
        return jsonify({
            "status": "connected",
            "message": "Google Gemini API Key successfully saved and connected!",
            "mode": "Gemini AI Active"
        })
    return jsonify({"error": "Failed to save API key"}), 500

@app.route("/api/scan/universal", methods=["POST"])
def api_scan_universal():
    """Inspect ANY arbitrary text (Code, Log, IP, URL, CVE, Query) on the fly."""
    data = request.get_json(silent=True) or {}
    input_data = data.get("input_data", "").strip()
    if not input_data:
        return jsonify({"error": "No input data provided"}), 400
    try:
        inspection = agent.universal_inspect(input_data)
        return jsonify({
            "success": True,
            "data": inspection,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": f"Universal inspection failed: {str(e)}"}), 500

# ==========================================
# 1. AI SOC CHAT / COPILOT
# ==========================================

@app.route("/api/chat", methods=["POST"])
def api_chat():
    """Chat with the SOC agent (autonomous reasoning or query answering)."""
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Message is required"}), 400

    try:
        response_text = agent.chat(message)
        return jsonify({
            "response": response_text,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })
    except Exception as e:
        return jsonify({"error": f"Agent error: {str(e)}"}), 500

@app.route("/api/chat/history", methods=["GET"])
def api_chat_history():
    """Return current conversation history."""
    return jsonify({"history": agent.memory.get_messages()})

@app.route("/api/chat/clear", methods=["POST"])
def api_chat_clear():
    """Clear memory and start fresh session."""
    agent.memory.clear()
    return jsonify({"status": "cleared", "message": "Agent memory reset successfully."})

# ==========================================
# 2. LOG THREAT ANALYZER
# ==========================================

@app.route("/api/scan/log", methods=["POST"])
def api_scan_log():
    """Analyze server logs via direct text or file upload."""
    log_content = ""
    target_name = "Raw Stream"

    if "file" in request.files:
        uploaded_file = request.files["file"]
        if uploaded_file.filename != "":
            target_name = uploaded_file.filename
            log_content = uploaded_file.read().decode("utf-8", errors="replace")
    elif request.is_json:
        data = request.get_json()
        log_content = data.get("log_content", "")
        target_name = data.get("target_name", "Pasted Log")
    else:
        log_content = request.form.get("log_content", "")
        target_name = request.form.get("target_name", "Pasted Log")

    if not log_content.strip():
        return jsonify({"error": "No log data provided"}), 400

    try:
        result = agent.log_analyzer.analyze_log_content(log_content)
        agent.memory.record_scan_result("LOG_ANALYSIS", target_name, result)
        
        # Also generate agent synthesis summary
        synthesis = agent._synthesize_log_analysis(result, target_name)

        return jsonify({
            "target": target_name,
            "result": result,
            "synthesis": synthesis,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": f"Log analysis failed: {str(e)}"}), 500

# ==========================================
# 3. SAST CODE SECURITY AUDITOR
# ==========================================

@app.route("/api/scan/code", methods=["POST"])
def api_scan_code():
    """Audit source code file or code text snippet."""
    code_content = ""
    filename = "snippet.py"

    if "file" in request.files:
        uploaded_file = request.files["file"]
        if uploaded_file.filename != "":
            filename = uploaded_file.filename
            code_content = uploaded_file.read().decode("utf-8", errors="replace")
    elif request.is_json:
        data = request.get_json()
        code_content = data.get("code_content", "")
        filename = data.get("filename", "snippet.py")
    else:
        code_content = request.form.get("code_content", "")
        filename = request.form.get("filename", "snippet.py")

    if not code_content.strip():
        return jsonify({"error": "No source code provided"}), 400

    try:
        result = agent.code_auditor.audit_code_content(filename, code_content)
        agent.memory.record_scan_result("CODE_AUDIT", filename, result)
        synthesis = agent._synthesize_code_audit(result, filename)

        return jsonify({
            "filename": filename,
            "result": result,
            "synthesis": synthesis,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": f"Code audit failed: {str(e)}"}), 500

# ==========================================
# 4. NETWORK RECON & HEADERS
# ==========================================

@app.route("/api/scan/network", methods=["POST"])
def api_scan_network():
    """Perform port scan or HTTP header posture audit."""
    data = request.get_json(silent=True) or {}
    scan_type = data.get("type", "ports")  # "ports" or "headers"
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Target host or URL is required"}), 400

    try:
        if scan_type == "ports":
            result = agent.scan_ports(target)
            synthesis = agent._synthesize_port_scan(result)
            return jsonify({
                "type": "ports",
                "target": target,
                "result": result,
                "synthesis": synthesis
            })
        else:
            result = agent.inspect_headers(target)
            synthesis = agent._synthesize_headers(result)
            return jsonify({
                "type": "headers",
                "target": target,
                "result": result,
                "synthesis": synthesis
            })
    except Exception as e:
        return jsonify({"error": f"Network reconnaissance failed: {str(e)}"}), 500

# ==========================================
# 5. CVE THREAT INTELLIGENCE
# ==========================================

@app.route("/api/cve/<cve_id>", methods=["GET"])
def api_cve(cve_id):
    """Retrieve CVE intelligence and mitigation playbook."""
    cve_clean = cve_id.strip().upper()
    try:
        data = agent.lookup_cve(cve_clean)
        synthesis = agent._synthesize_cve(data, cve_clean)
        return jsonify({
            "cve_id": cve_clean,
            "data": data,
            "synthesis": synthesis
        })
    except Exception as e:
        return jsonify({"error": f"CVE query failed: {str(e)}"}), 500

# ==========================================
# 6. INCIDENT REPORT EXPORT
# ==========================================

@app.route("/api/report", methods=["GET"])
def api_report():
    """Generate markdown incident report."""
    try:
        markdown_report = agent.generate_incident_report()
        return jsonify({
            "report_markdown": markdown_report,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500

@app.route("/api/report/download", methods=["GET"])
def api_report_download():
    """Download incident report as a .md file."""
    try:
        markdown_report = agent.generate_incident_report()
        mem = io.BytesIO(markdown_report.encode("utf-8"))
        filename = f"cybersentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        return send_file(
            mem,
            as_attachment=True,
            download_name=filename,
            mimetype="text/markdown"
        )
    except Exception as e:
        return jsonify({"error": f"Download failed: {str(e)}"}), 500

# ==========================================
# SAMPLE DATA LOADERS (For One-Click Testing)
# ==========================================

@app.route("/api/samples/log", methods=["GET"])
def api_sample_log():
    """Return content of sample access.log."""
    sample_path = os.path.join(BASE_DIR, "samples", "access.log")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"filename": "access.log", "content": content})
    return jsonify({"error": "Sample log not found"}), 404

@app.route("/api/samples/code", methods=["GET"])
def api_sample_code():
    """Return content of sample vulnerable_app.py."""
    sample_path = os.path.join(BASE_DIR, "samples", "vulnerable_app.py")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"filename": "vulnerable_app.py", "content": content})
    return jsonify({"error": "Sample code not found"}), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n=======================================================")
    print(f"🛡️  CYBERSENTINEL AI - SOC OPERATIONS DASHBOARD")
    print(f"🚀  Running on: http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    app.run(host="127.0.0.1", port=port, debug=False)
