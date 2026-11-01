import os
import unittest

try:
    from streamlit.testing.v1 import AppTest
except ImportError:  # Streamlit not installed
    AppTest = None

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


@unittest.skipIf(AppTest is None, "Streamlit is not installed")
class DashboardSmokeTest(unittest.TestCase):
    def test_dashboard_renders_without_exceptions(self):
        at = AppTest.from_file(APP, default_timeout=60).run()
        self.assertFalse(at.exception, at.exception)


if __name__ == "__main__":
    unittest.main()
