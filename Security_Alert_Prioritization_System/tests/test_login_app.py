import json
import os
import tempfile
import unittest

try:
    from demo_app import login_app
except ImportError:  # Flask not installed
    login_app = None


@unittest.skipIf(login_app is None, "Flask is not installed")
class LoginAppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
        self.tmp.close()
        self._original = login_app.LOG_FILE
        login_app.LOG_FILE = self.tmp.name
        self.client = login_app.app.test_client()

    def tearDown(self):
        login_app.LOG_FILE = self._original
        os.unlink(self.tmp.name)

    def events(self):
        with open(self.tmp.name, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_wrong_password_is_logged_and_rejected(self):
        response = self.client.post("/login", data={"username": "admin", "password": "nope"})
        self.assertEqual(response.status_code, 401)
        event = self.events()[0]
        self.assertEqual(event["event_type"], "LOGIN_FAILED")
        self.assertEqual(event["username"], "admin")

    def test_correct_password_is_logged_as_success(self):
        response = self.client.post(
            "/login",
            data={"username": login_app.DEMO_USERNAME, "password": login_app.DEMO_PASSWORD},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.events()[0]["event_type"], "LOGIN_SUCCESS")

    def test_missing_fields_do_not_crash(self):
        self.assertEqual(self.client.post("/login", data={}).status_code, 401)

    def test_long_input_is_truncated(self):
        self.client.post("/login", data={"username": "u" * 5000, "password": "x"})
        self.assertEqual(len(self.events()[0]["username"]), login_app.MAX_FIELD_LENGTH)

    def test_login_page_renders(self):
        self.assertEqual(self.client.get("/").status_code, 200)


if __name__ == "__main__":
    unittest.main()
