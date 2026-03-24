from flask import Flask, request, jsonify
import re
import json
import time
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

# ─── ATTACK SIGNATURES ─────────────────────────────────────────────────────────
RULES = [
    {
        "name": "SQL Injection",
        "category": "SQLi",
        "pattern": re.compile(
           r"(%20|\s|'|\"|\+)*(or|and|union|select|insert|drop|delete|--|xp_|exec\s*\()",
        )
    },
    {
        "name": "XSS - Cross Site Scripting",
        "category": "XSS",
        "pattern": re.compile(
            r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(",
            re.IGNORECASE
        )
    },
    {
        "name": "Local File Inclusion",
        "category": "LFI",
        "pattern": re.compile(
            r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|/windows/system",
            re.IGNORECASE
        )
    },
    {
        "name": "Command Injection",
        "category": "CMDi",
        "pattern": re.compile(
            r"[;|`]\s*(ls|cat|rm|wget|curl|bash|sh|cmd|powershell)",
            re.IGNORECASE
        )
    },
    {
        "name": "Directory Traversal",
        "category": "DirTraversal",
        "pattern": re.compile(
            r"(%2e%2e|%252e|\.{2,}/)",
            re.IGNORECASE
        )
    },
]

# ─── RATE LIMITER ───────────────────────────────────────────────────────────────
request_tracker = defaultdict(list)   # ip -> [timestamps]
RATE_LIMIT = 10      # max requests
TIME_WINDOW = 60     # in seconds
blocked_ips = set()

def check_rate_limit(ip):
    now = time.time()
    # Remove old timestamps outside the window
    request_tracker[ip] = [t for t in request_tracker[ip] if now - t < TIME_WINDOW]
    request_tracker[ip].append(now)
    if len(request_tracker[ip]) > RATE_LIMIT:
        blocked_ips.add(ip)
        return True   # rate limit exceeded
    return False

# ─── LOGGER ─────────────────────────────────────────────────────────────────────
LOG_FILE = "sentinel_log.json"

def log_event(ip, url, action, category=None, rule=None):
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "url": url,
        "action": action,
        "category": category,
        "rule": rule
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[{entry['timestamp']}] {action:7} | {ip:15} | {category or 'CLEAN':12} | {url[:60]}")
    return entry

# ─── MAIN INSPECTION ENGINE ──────────────────────────────────────────────────────
def inspect_request(ip, url, headers, body=""):
    # Check if IP is already blocked for rate abuse
    if ip in blocked_ips:
        return log_event(ip, url, "BLOCKED", "RateLimit", "IP banned")

    # Check rate limit
    if check_rate_limit(ip):
        return log_event(ip, url, "BLOCKED", "RateLimit", "Too many requests")

    # Combine everything to inspect
    full_content = url + " " + str(headers) + " " + body

    # Run through all rules
    for rule in RULES:
        if rule["pattern"].search(full_content):
            return log_event(ip, url, "BLOCKED", rule["category"], rule["name"])

    # All clear
    return log_event(ip, url, "ALLOWED")

# ─── WEB ROUTES ─────────────────────────────────────────────────────────────────
@app.route("/inspect", methods=["GET", "POST"])
def inspect():
    ip = request.remote_addr
    url = request.full_path
    headers = dict(request.headers)
    body = request.get_data(as_text=True)
    result = inspect_request(ip, url, headers, body)
    status = 200 if result["action"] == "ALLOWED" else 403
    return jsonify(result), status

@app.route("/dashboard")
def dashboard():
    stats = {"total": 0, "blocked": 0, "allowed": 0, "by_category": {}, "flagged_ips": list(blocked_ips)}
    try:
        with open(LOG_FILE) as f:
            for line in f:
                e = json.loads(line)
                stats["total"] += 1
                if e["action"] == "BLOCKED":
                    stats["blocked"] += 1
                    cat = e["category"] or "Unknown"
                    stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
                else:
                    stats["allowed"] += 1
    except FileNotFoundError:
        pass
    return jsonify(stats)

@app.route("/")
def index():
    return """
    <h2>SentinelShield WAF</h2>
    <p>Send requests to <code>/inspect?param=value</code> to test detection.</p>
    <p>View stats at <a href='/dashboard'>/dashboard</a></p>
    """

if __name__ == "__main__":
    print("SentinelShield WAF running on http://localhost:5000")
    app.run(debug=True, port=5000)