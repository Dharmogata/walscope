"""Comprehensive unit test suite for WalScope."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest

from walscope.analyzer import explain_queries, get_rules, inspect_database
from walscope.binary_parser import (
    InvalidSQLiteHeaderError,
    WAL_FRAME_HEADER_SIZE,
    WAL_HEADER_SIZE,
    WAL_MAGIC_BIG_ENDIAN,
    parse_database_header,
    parse_wal_file,
)
from walscope.cli import main


class WalScopeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _create_base_db(self, name: str = "sample.db", page_size: int = 4096) -> Path:
        db_path = self.tmp_dir / name
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(f"PRAGMA page_size = {page_size};")
            conn.execute("PRAGMA user_version = 42;")
            conn.execute("PRAGMA application_id = 0x57414C53;")
            conn.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE
                );
                """
            )
            conn.commit()
        finally:
            conn.close()
        return db_path

    def _write_synthetic_wal(
        self,
        db_path: Path,
        page_size: int = 4096,
        frame_pages: list[int] | None = None,
        salt_1: int = 0xAABBCCDD,
        salt_2: int = 0x11223344,
    ) -> Path:
        wal_path = Path(f"{db_path}-wal")
        pages = frame_pages if frame_pages is not None else [1, 2, 3]
        header = struct.pack(
            ">IIIIIIII",
            WAL_MAGIC_BIG_ENDIAN,
            3007000,
            page_size,
            1,
            salt_1,
            salt_2,
            0,
            0,
        )
        assert len(header) == WAL_HEADER_SIZE
        chunks = [header]
        payload = b"\x00" * page_size
        for page_no in pages:
            frame_hdr = struct.pack(
                ">IIIIII",
                page_no,
                len(pages),
                salt_1,
                salt_2,
                0,
                0,
            )
            assert len(frame_hdr) == WAL_FRAME_HEADER_SIZE
            chunks.append(frame_hdr)
            chunks.append(payload)
        wal_path.write_bytes(b"".join(chunks))
        return wal_path

    def test_parse_database_header_fields(self) -> None:
        db_path = self._create_base_db(page_size=4096)
        hdr = parse_database_header(db_path)
        self.assertEqual(hdr.page_size, 4096)
        self.assertGreaterEqual(hdr.page_count, 2)
        self.assertEqual(hdr.freelist_pages, 0)
        self.assertEqual(hdr.text_encoding, "UTF-8")
        self.assertEqual(hdr.user_version, 42)
        self.assertEqual(hdr.application_id, 0x57414C53)
        self.assertFalse(hdr.wal_mode)
        self.assertEqual(hdr.fragmentation_ratio, 0.0)
        self.assertEqual(hdr.fragmentation_Ratio, 0.0)

    def test_invalid_database_header_raises(self) -> None:
        bad_file = self.tmp_dir / "not_a_db.db"
        bad_file.write_bytes(b"not a valid sqlite database file at all" * 5)
        with self.assertRaises(InvalidSQLiteHeaderError):
            parse_database_header(bad_file)

    def test_parse_wal_file_summary_and_dirty_pages(self) -> None:
        db_path = self._create_base_db(page_size=4096)
        # Frames writing page 2 twice, page 5 once, page 9 once -> 4 frames, 3 unique dirty pages
        self._write_synthetic_wal(db_path, page_size=4096, frame_pages=[2, 5, 2, 9])
        wal = parse_wal_file(db_path, fallback_page_size=4096)
        self.assertTrue(wal.exists)
        self.assertEqual(wal.frame_count, 4)
        self.assertEqual(wal.uncheckpointed_pages, 3)
        self.assertEqual(wal.dirty_page_numbers, [2, 5, 9])
        self.assertEqual(wal.checkpoint_pressure, "LOW")

    def test_rule_ws001_unindexed_foreign_key(self) -> None:
        db_path = self._create_base_db()
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                """
                CREATE TABLE orders (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    total_cents INTEGER NOT NULL
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

        report = inspect_database(db_path)
        ws001 = [f for f in report.findings if f.rule_id == "WS001"]
        self.assertEqual(len(ws001), 1)
        self.assertEqual(ws001[0].target, "orders(user_id)")

        # Now add a covering index and verify WS001 clears
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("CREATE INDEX idx_orders_user_id ON orders(user_id);")
            conn.commit()
        finally:
            conn.close()

        report_after = inspect_database(db_path)
        self.assertEqual([f for f in report_after.findings if f.rule_id == "WS001"], [])

    def test_rule_ws002_freelist_fragmentation(self) -> None:
        db_path = self._create_base_db(page_size=4096)
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA auto_vacuum = NONE;")
            conn.executemany(
                "INSERT INTO users (email) VALUES (?);",
                [(f"user_{i}_{'x' * 200}@example.com",) for i in range(400)],
            )
            conn.commit()
            conn.execute("DELETE FROM users WHERE id > 10;")
            conn.commit()
        finally:
            conn.close()

        report = inspect_database(db_path)
        self.assertGreater(report.header.freelist_pages, 0)
        self.assertGreaterEqual(report.header.fragmentation_ratio, 0.10)
        ws002 = [f for f in report.findings if f.rule_id == "WS002"]
        self.assertEqual(len(ws002), 1)

    def test_rule_ws003_wal_checkpoint_backlog(self) -> None:
        db_path = self._create_base_db(page_size=4096)
        # Write 105 frames (>100 frame threshold)
        self._write_synthetic_wal(
            db_path,
            page_size=4096,
            frame_pages=[(i % 20) + 1 for i in range(105)],
        )
        report = inspect_database(db_path)
        self.assertEqual(report.wal.frame_count, 105)
        self.assertEqual(report.wal.checkpoint_pressure, "HIGH")
        ws003 = [f for f in report.findings if f.rule_id == "WS003"]
        self.assertEqual(len(ws003), 1)

    def test_rule_ws004_table_missing_primary_key(self) -> None:
        db_path = self._create_base_db()
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("CREATE TABLE audit_logs (ts TEXT, payload TEXT);")
            conn.commit()
        finally:
            conn.close()

        report = inspect_database(db_path)
        ws004 = [f for f in report.findings if f.rule_id == "WS004"]
        self.assertEqual(len(ws004), 1)
        self.assertEqual(ws004[0].target, "audit_logs")

    def test_rule_ws005_explain_query_plan_full_scan(self) -> None:
        db_path = self._create_base_db()
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, kind TEXT);")
            conn.commit()
        finally:
            conn.close()

        steps = explain_queries(
            db_path,
            [
                "SELECT * FROM events WHERE kind = 'signup'",
                "SELECT * FROM users WHERE email = 'a@b.com'",
            ],
        )
        self.assertTrue(any(s.is_full_scan for s in steps))
        self.assertTrue(any(not s.is_full_scan for s in steps))

        report = inspect_database(
            db_path,
            queries=["SELECT * FROM events WHERE kind = 'signup'"],
        )
        ws005 = [f for f in report.findings if f.rule_id == "WS005"]
        self.assertEqual(len(ws005), 1)
        self.assertEqual(ws005[0].target, "events")

    def test_cli_subcommands_inspect_header_rules(self) -> None:
        db_path = self._create_base_db()

        # 1. rules JSON
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["rules", "--format", "json"])
        self.assertEqual(rc, 0)
        rules_data = json.loads(buf.getvalue())
        self.assertEqual(len(rules_data), len(get_rules()))

        # 2. header JSON
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["header", str(db_path), "--format", "json"])
        self.assertEqual(rc, 0)
        hdr_data = json.loads(buf.getvalue())
        self.assertEqual(hdr_data["header"]["page_size"], 4096)

        # 3. inspect markdown & text
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(
                [
                    "inspect",
                    str(db_path),
                    "--query",
                    "SELECT * FROM users WHERE email = 'x@y.com'",
                    "--format",
                    "markdown",
                ]
            )
        self.assertEqual(rc, 0)
        self.assertIn("# WalScope X-Ray Report", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
