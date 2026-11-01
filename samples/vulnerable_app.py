"""
Vulnerable Sample Web Application for CyberSentinel SAST Audit
Contains intentional security flaws for demonstration and testing purposes.
"""

import os
import subprocess
import pickle
import hashlib
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# FLAW 1: Hardcoded AWS Secret Key and Database Password
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DATABASE_PASSWORD = "SuperSecretAdminPassword123!"

# FLAW 2: Insecure Deserialization via pickle
@app.route("/api/session/load", methods=["POST"])
def load_session():
    user_payload = request.data
    # Insecure: untrusted user data deserialized directly
    session_obj = pickle.loads(user_payload)
    return jsonify({"status": "loaded", "session": str(session_obj)})

# FLAW 3: SQL Injection via direct f-string string interpolation
@app.route("/api/users", methods=["GET"])
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Insecure SQL concatenation
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    return jsonify({"users": results})

# FLAW 4: Command Injection via shell=True
@app.route("/api/network/ping", methods=["GET"])
def ping_host():
    target = request.args.get("host", "127.0.0.1")
    # Insecure shell command execution with unsanitized user variable
    output = subprocess.check_output(f"ping -c 1 {target}", shell=True)
    return output

# FLAW 5: Weak cryptographic hashing (MD5) for passwords
def hash_user_password(password: str) -> str:
    # Insecure: MD5 is vulnerable to collision attacks
    return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    # FLAW 6: Interactive Debug mode enabled in production
    app.run(host="0.0.0.0", port=5000, debug=True)
