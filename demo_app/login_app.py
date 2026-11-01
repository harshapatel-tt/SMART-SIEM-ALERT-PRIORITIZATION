import json
import os
import sys
from datetime import datetime

from flask import Flask, request, render_template_string

# Make the project root importable when run as `python demo_app/login_app.py`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings  # noqa: E402

app = Flask(__name__)

# Same log file the SIEM collector reads (SIEM_LOG_FILE in .env)
LOG_FILE = str(settings.LOG_FILE)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


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

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


@app.route("/", methods=["GET"])
def home():

    return render_template_string(LOGIN_PAGE)


def client_ip():
    """Real peer address. For demos from a single machine every request
    comes from 127.0.0.1, so (only if DEMO_ALLOW_SIMULATED_IP=true) the
    X-Simulated-Source-IP header may override it. Never enable that in
    anything but a local demo."""
    if settings.DEMO_ALLOW_SIMULATED_IP:
        simulated = request.headers.get("X-Simulated-Source-IP")
        if simulated:
            return simulated.strip()
    return request.remote_addr


@app.route("/login", methods=["POST"])
def login():

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    ip_address = client_ip()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Demo credentials come from the environment (see .env.example)
    if username == settings.DEMO_USERNAME and password == settings.DEMO_PASSWORD:

        event = {
            "timestamp": timestamp,
            "event_type": "LOGIN_SUCCESS",
            "username": username,
            "source_ip": ip_address,
            "resource": "Demo Web Application",
        }

        write_log(event)

        return "<h2>Login Successful</h2>"

    else:

        event = {
            "timestamp": timestamp,
            "event_type": "LOGIN_FAILED",
            "username": username or "unknown",
            "source_ip": ip_address,
            "resource": "Demo Web Application",
        }

        write_log(event)

        return "<h2>Login Failed</h2>", 401


if __name__ == "__main__":

    print("Security Demo Application Started")
    print(f"Open: http://{settings.DEMO_APP_HOST}:{settings.DEMO_APP_PORT}")

    app.run(
        host=settings.DEMO_APP_HOST,
        port=settings.DEMO_APP_PORT,
        debug=settings.DEMO_DEBUG
    )