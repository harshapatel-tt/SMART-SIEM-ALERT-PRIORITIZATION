"""
Fires a burst of wrong-password logins at the running demo app so the
detector has something to find.

1. Start the demo app:   python demo_app/login_app.py
2. Run this script:      python demo_app/simulate_attack.py [attempts]
3. Refresh the dashboard (streamlit run app.py): a Brute Force alert appears.
"""

import sys
import urllib.error
import urllib.parse
import urllib.request

URL = "http://127.0.0.1:5000/login"


def main(attempts=8, username="admin"):
    for i in range(1, attempts + 1):
        data = urllib.parse.urlencode(
            {"username": username, "password": f"wrong-password-{i}"}
        ).encode()

        try:
            urllib.request.urlopen(URL, data=data, timeout=5)
        except urllib.error.HTTPError as error:
            status = error.code  # 401 is the expected "login failed"
        except urllib.error.URLError as error:
            print(f"Could not reach {URL} - is the demo app running? ({error.reason})")
            return 1
        else:
            status = 200

        print(f"Attempt {i}/{attempts}: HTTP {status}")

    print(f"\nSent {attempts} failed logins for '{username}'.")
    return 0


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    sys.exit(main(count))
