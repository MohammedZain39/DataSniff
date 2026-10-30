import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from pypdf import PdfReader
from io import BytesIO

from services.reporting import build_pdf_report, prepare_report
from services.scan_store import list_scans


def make_scan(findings, **overrides):
    scan = {"id": 17, "filename": "C:\\logs\\application.log", "scanned_at": "2026-10-30T09:15:00+05:30", "findings_json": json.dumps(findings)}
    scan.update(overrides)
    return scan


class PdfReportTests(unittest.TestCase):
    def pdf_text(self, scan):
        data, metadata = build_pdf_report(scan)
        reader = PdfReader(BytesIO(data))
        return data, metadata, reader, "\n".join(page.extract_text() or "" for page in reader.pages)

    def test_zero_findings_report_has_summary_and_pagination(self):
        data, metadata, reader, text = self.pdf_text(make_scan([]))
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertEqual(metadata["severity_counts"], {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
        self.assertIn("No matching findings", text)
        for number, page in enumerate(reader.pages, 1):
            self.assertIn(f"Page {number}", page.extract_text())

    def test_one_finding_includes_location_and_category_guidance(self):
        item = {"category": "Database connection string", "severity": "Critical", "confidence": 98, "file": "application.log", "line": 125, "evidence": "adm***********42", "explanation": "Credential-bearing database URI detected.", "remediation": "Rotate the password."}
        _, metadata, _, text = self.pdf_text(make_scan([item]))
        self.assertEqual(metadata["severity_counts"]["Critical"], 1)
        self.assertIn("Line 125", text)
        self.assertIn("Database connection string", text)
        self.assertIn("Rotate the database password", text)
        self.assertIn("Verification", text)

    def test_multiple_findings_all_severities_use_actual_counts(self):
        findings = [
            {"category": "Private key", "severity": "Critical", "confidence": 98, "line": 1, "evidence": "-----BEGIN PRIVATE KEY-----"},
            {"category": "API token", "severity": "High", "confidence": 94, "line": 2, "evidence": "sk_live_abcd"},
            {"category": "Phone number", "severity": "Medium", "confidence": 83, "line": 3, "evidence": "+1 415 555 0199"},
            {"category": "Email address", "severity": "Low", "confidence": 88, "line": 4, "evidence": "person@example.test"},
        ]
        _, metadata, reader, text = self.pdf_text(make_scan(findings))
        self.assertEqual(metadata["severity_counts"], {"Critical": 1, "High": 1, "Medium": 1, "Low": 1})
        self.assertEqual(len(metadata["findings"]), 4)
        self.assertGreaterEqual(len(reader.pages), 4)
        self.assertIn("Revoke or rotate the key", text)
        self.assertIn("Private key", text)

    def test_redacts_raw_tokens_and_paths_and_wraps_long_text(self):
        synthetic_token = "sk_live_" + "A" * 180
        finding = {"category": "API token", "severity": "High", "confidence": 94, "line": 9, "file": "D:\\private\\prod.log", "evidence": synthetic_token, "explanation": "Résumé: candidate token found.", "remediation": "Review " + ("long remediation instruction " * 90)}
        _, metadata, reader, text = self.pdf_text(make_scan([finding], filename="D:\\private\\prod.log"))
        self.assertNotIn(synthetic_token, text)
        self.assertNotIn("D:\\private", text)
        self.assertEqual(metadata["source_file"], "prod.log")
        self.assertIn("Résumé", text)
        self.assertGreater(len(reader.pages), 3)

    def test_malformed_findings_and_unicode_are_safe(self):
        report = prepare_report(make_scan([], filename="café-résumé.log", findings_json="{bad json"))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["source_file"], "café-résumé.log")
        data, _, reader, _ = self.pdf_text(make_scan([], filename="café-résumé.log", findings_json="{bad json"))
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertGreaterEqual(len(reader.pages), 3)

    def test_finding_without_line_uses_structured_path(self):
        finding = {"category": "Email address", "severity": "Low", "confidence": 88, "path": "events[2].actor.email", "evidence": "u***t"}
        _, _, _, text = self.pdf_text(make_scan([finding]))
        self.assertIn("events[2].actor.email", text)

    def test_authorized_scan_list_excludes_other_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = str(Path(directory) / "scans.sqlite3")
            con = sqlite3.connect(db_path)
            try:
                con.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, filename TEXT, scanned_at TEXT, findings_json TEXT, size_bytes INTEGER, owner_id INTEGER)")
                con.execute("INSERT INTO scans VALUES (1,'mine.log','now','[]',1,101)")
                con.execute("INSERT INTO scans VALUES (2,'other.log','now','[]',1,202)")
                con.commit()
            finally:
                con.close()
            self.assertEqual([row["filename"] for row in list_scans(db_path, owner_id=101)], ["mine.log"])
            self.assertEqual(len(list_scans(db_path)), 2)


if __name__ == "__main__":
    unittest.main()
