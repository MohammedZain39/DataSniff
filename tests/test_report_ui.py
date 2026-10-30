import os
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


class ReportUiTests(unittest.TestCase):
    def test_scan_results_can_generate_and_download_pdf(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {
            "DATASNIFF_AUTH_MODE": "local",
            "DATASNIFF_DB_PATH": os.path.join(temp_dir, "ui-test.sqlite3"),
        }):
            app = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app.py")).run()
            app.session_state["nav_page"] = "New Scan"
            app.session_state["last_scan"] = {
                "scan_id": 77,
                "filename": "synthetic.log",
                "findings": [{
                    "category": "API token", "severity": "High", "confidence": 94,
                    "file": "synthetic.log", "line": 3, "evidence": "sk_************xy",
                    "explanation": "Synthetic token pattern.", "remediation": "Rotate if genuine.",
                }],
            }
            app.run()
            self.assertFalse(app.exception)
            self.assertEqual([button.label for button in app.button], ["Generate Security Report"])
            app.button[0].click().run()
            self.assertFalse(app.exception)
            self.assertEqual(len(app.get("download_button")), 1)


if __name__ == "__main__":
    unittest.main()
