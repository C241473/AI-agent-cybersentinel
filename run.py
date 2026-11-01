"""
CyberSentinel AI - Web Application Runner
"""
import os
import sys

# Ensure project directory is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Ensure UTF-8 output encoding for Windows console
if sys.platform.startswith("win"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("=" * 60)
    print("🛡️  CyberSentinel AI - Autonomous SOC Operations Center")
    print(f"🚀  Local Dashboard: http://127.0.0.1:{port}")
    print("=" * 60)
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
