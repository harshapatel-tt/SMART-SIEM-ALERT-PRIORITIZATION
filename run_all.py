
import subprocess
import sys
import time
import requests
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

processes = []

try:
    print("Starting SIEM Backend...")

    backend = subprocess.Popen(
        [sys.executable, "-m", "backend.api"],
        cwd=BASE_DIR
    )
    processes.append(backend)

    # Wait for backend API
    for i in range(30):
        if backend.poll() is not None:
            raise RuntimeError("Backend stopped. Check backend errors.")

        try:
            response = requests.get(
                "http://127.0.0.1:8000/api/dashboard/summary",
                timeout=2
            )
            if response.ok:
                print("Backend is ready!")
                break
        except requests.RequestException:
            pass

        time.sleep(2)
    else:
        raise RuntimeError("Backend did not become ready.")

    print("Starting Demo Web Application...")
    demo = subprocess.Popen(
        [sys.executable, "demo_app/login_app.py"],
        cwd=BASE_DIR
    )
    processes.append(demo)

    print("Starting Streamlit Dashboard...")
    dashboard = subprocess.Popen(
        [
            sys.executable, "-m", "streamlit",
            "run", "app.py"
        ],
        cwd=BASE_DIR
    )
    processes.append(dashboard)

    print("SIEM Project Started!")
    print("Backend: http://127.0.0.1:8000")
    print("Dashboard: http://localhost:8501")

    dashboard.wait()

except KeyboardInterrupt:
    print("Stopping SIEM Project...")

except Exception as error:
    print("Error:", error)

finally:
    for process in processes:
        if process.poll() is None:
            process.terminate()
