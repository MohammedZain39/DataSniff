"""Authorized scan-list queries shared by the UI and report selection."""
import sqlite3


def list_scans(db_path, owner_id=None):
    con = sqlite3.connect(db_path)
    try:
        con.row_factory = sqlite3.Row
        if owner_id is None:
            rows = con.execute("SELECT * FROM scans ORDER BY id DESC")
        else:
            rows = con.execute("SELECT * FROM scans WHERE owner_id=? ORDER BY id DESC", (owner_id,))
        return [dict(row) for row in rows]
    finally:
        con.close()
