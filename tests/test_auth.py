import tempfile
import unittest
import sqlite3
from pathlib import Path

from auth_core import LOCK_SECONDS, authenticate, init_auth_db, register, validate_registration


class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "auth.sqlite3"
        init_auth_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_registration_hashes_password_and_login_works(self):
        self.assertIsNone(validate_registration("Ada", "ada@example.test", "StrongPassword123", "StrongPassword123", True))
        self.assertTrue(register("Ada", "ADA@example.test", "StrongPassword123", self.db))
        with sqlite3.connect(self.db) as con:
            stored = con.execute("SELECT password_hash FROM accounts WHERE email=?", ("ada@example.test",)).fetchone()[0]
        self.assertNotEqual(stored, b"StrongPassword123")
        self.assertTrue(bytes(stored).startswith(b"$2b$"))
        self.assertFalse(register("Ada", "ada@example.test", "DifferentPassword456", self.db))
        account = authenticate("ada@example.test", "StrongPassword123", self.db)
        self.assertEqual(account["full_name"], "Ada")
        self.assertIsNone(authenticate("ada@example.test", "wrong-password", self.db))

    def test_registration_validation(self):
        self.assertIn("valid email", validate_registration("Ada", "bad", "StrongPassword123", "StrongPassword123", True))
        self.assertIn("do not match", validate_registration("Ada", "ada@example.test", "StrongPassword123", "DifferentPassword456", True))
        self.assertIn("Accept", validate_registration("Ada", "ada@example.test", "StrongPassword123", "StrongPassword123", False))
        self.assertIn("12 and 64", validate_registration("Ada", "ada@example.test", "Short1a", "Short1a", True))

    def test_repeated_failures_lock_account_attempts(self):
        register("Ada", "ada@example.test", "StrongPassword123", self.db)
        for _ in range(5):
            self.assertIsNone(authenticate("ada@example.test", "incorrect", self.db, now=1000))
        self.assertIsNone(authenticate("ada@example.test", "StrongPassword123", self.db, now=1001))
        account = authenticate("ada@example.test", "StrongPassword123", self.db, now=1000 + LOCK_SECONDS + 1)
        self.assertEqual(account["email"], "ada@example.test")


if __name__ == "__main__":
    unittest.main()
