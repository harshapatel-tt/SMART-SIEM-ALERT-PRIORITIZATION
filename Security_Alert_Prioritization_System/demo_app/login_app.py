"""
Tiny Flask login page that produces the security events the rest of the
project analyses (LOGIN_SUCCESS / LOGIN_FAILED written to logs/security.log).

Run:  python demo_app/login_app.py
"""

import hmac
import json
import os
import threading
from datetime import datetime

from flask import Flask, render_template_string, request

app = Flask(__name__)

# Project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "security.log")

os.makedirs(LOG_DIR, exist_ok=True)

# Demo credentials. Override with environment variables if you like.
DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "admin")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "Admin@123")

MAX_FIELD_LENGTH = 100
_log_lock = threading.Lock()


LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Demo Login</title>

    <style>
        body {
            font-family: Arial;
            background: #f2f2f2;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .login-box {
            background: white;
            padding: 30px;
            width: 320px;
            border-radius: 10px;
            box-shadow: 0 0 10px #aaa;
        }

        input {
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            box-sizing: border-box;
        }

        button {
            width: 100%;
            padding: 10px;
            background: #333;
            color: white;
            border: none;
            cursor: pointer;
        }
    </style>
</head>

<body>

<div class="login-box">

    <h2>Security Demo Login</h2>

    <form method="POST" action="/login">

        <input
            type="text"
            name="username"
            placeholder="Username"
            required
        >

        <input
            type="password"
            name="password"
            placeholder="Password"
            required
        >

        <button type="submit">Login</button>

    </form>

</div>

</body>
</html>
"""


def write_log(event):
    """Appends one JSON event per line (thread-safe)."""

    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")


def _credentials_match(username, password):
    """Constant-time comparison so response timing leaks nothing."""

    user_ok = hmac.compare_digest(username.encode(), DEMO_USERNAME.encode())
    pass_ok = hmac.compare_digest(password.encode(), DEMO_PASSWORD.encode())

    return user_ok and pass_ok


@app.route("/", methods=["GET"])
def home():

    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["POST"])
def login():

    username = (request.form.get("username") or "")[:MAX_FIELD_LENGTH]
    password = (request.form.get("password") or "")[:MAX_FIELD_LENGTH]

    ip_address = request.remote_addr

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    success = _credentials_match(username, password)

    write_log(
        {
            "timestamp": timestamp,
            "event_type": "LOGIN_SUCCESS" if success else "LOGIN_FAILED",
            "username": username,
            "source_ip": ip_address,
        }
    )

    if success:
        return "<h2>Login Successful</h2>"

    return "<h2>Login Failed</h2>", 401


if __name__ == "__main__":

    print("Security Demo Application Started")
    print("Open: http://127.0.0.1:5000")
    print("LOG FILE:", LOG_FILE)

    # debug=True exposes the Werkzeug debugger (remote code execution),
    # so it is opt-in only: set FLASK_DEBUG=1 if you really want it.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
