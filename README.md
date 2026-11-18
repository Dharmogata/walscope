# WalScope

**WalScope** is a command-line SQLite binary header, Write-Ahead Log (`.db-wal`) frame stream, schema index, and `EXPLAIN QUERY PLAN` X-Ray inspector.

While standard SQLite shell commands require running manual `PRAGMA` queries one by one, WalScope directly unpacks the 100-byte `SQLite format 3\x00` binary database header and 32-byte `.db-wal` frame stream alongside read-only schema and query-plan introspection—catching unindexed foreign keys, freelist page fragmentation, WAL checkpoint starvation, missing primary keys, and accidental full table scans in a single pass.

---

## Who It's For

- **Backend, mobile, and edge engineers** running SQLite in production (Litestream, Turso/libSQL, Rails/Django/FastAPI, embedded devices) who need instant visibility into WAL growth and page fragmentation.
- **Database and CI maintainers** validating schema migrations and critical SQL queries against unindexed foreign keys (`WS001`) and full table scans (`WS005`).

---

## What It's Built With

- **Language:** Python 3.10+
- **Core Architecture:** Pure Python standard library (`sqlite3`, `struct`, `argparse`, `pathlib`, `json`, `dataclasses`, `unittest`) with **zero external runtime dependencies**.
- **Test Suite:** Compatible with both `pytest` and `python -m unittest`.

---

## Features

- **100-Byte SQLite Binary Header Parser (`binary_parser.py`):** Directly unpacks big-endian binary header fields (`page_size`, `page_count`, `freelist_pages`, `first_freelist_trunk_page`, `schema_cookie`, `schema_format`, `text_encoding`, `user_version`, `application_id`, and WAL read/write format versions).
- **WAL Frame Stream X-Ray (`.db-wal`):** Parses the 32-byte WAL header (`0x377f0682` / `0x377f0683` magic, salts, checkpoint sequence) and walks 24-byte frame headers to count active frames and unique uncheckpointed dirty pages.
- **Built-in Storage & Schema Rules (`WS001` – `WS005`):**
  - `WS001` (`HIGH` / `unindexed-foreign-key`): Foreign key column on a child table lacks a covering index prefix, risking full table scans on parent updates or deletes.
  - `WS002` (`MEDIUM` / `freelist-fragmentation`): Database freelist page ratio exceeds threshold (`>=10%` wasted pages), recommending `VACUUM` or `PRAGMA auto_vacuum`.
  - `WS003` (`HIGH` / `wal-checkpoint-backlog`): Companion `.db-wal` file exceeds frame (`>100` frames) or byte (`>4 MB`) threshold, indicating checkpoint starvation.
  - `WS004` (`MEDIUM` / `table-missing-primary-key`): Table lacks an explicit `PRIMARY KEY` definition.
  - `WS005` (`HIGH` / `full-table-scan-query`): `EXPLAIN QUERY PLAN` on a user-supplied SQL query reveals a `SCAN <table>` without an index.
- **Multiple Output Formats:** Terminal X-Ray view (`text`), structured `json`, and `markdown` reports.

```text
$ walscope inspect app.db --query "SELECT * FROM orders WHERE total_cents > 1000"

WalScope X-Ray Report (app.db)
══════════════════════════════════════════════════════════════════════════════
[Binary Header & Storage]
  Page Size: 4,096 B | Pages: 48 (196,608 B) | Freelist: 9 (18.8%)
  Encoding : UTF-8 | Mode: WAL | Schema Format: 4 | User Version: 42

[Write-Ahead Log (.db-wal)]
  Status: PRESENT (442,400 B) | Frames: 107 | Dirty Pages: 19 | Pressure: HIGH

[Schema Tables (3)]
  - audit_logs           rows=1200   cols=2   indexes=0   PK:NO 
  - orders               rows=850    cols=3   indexes=0   PK:YES | Unindexed FK: user_id -> users
  - users                rows=140    cols=2   indexes=1   PK:YES

[Query Plan X-Ray (1 step(s))]
  [SCAN!] SCAN orders  (sql: SELECT * FROM orders WHERE total_cents > 1000)

[Diagnostic Findings (4)]
  [WS001/HIGH] orders(user_id) — Foreign key 'user_id -> users' on table 'orders' lacks a covering index prefix.
     └ Advice: Create an index: CREATE INDEX idx_orders_user_id ON orders (user_id);
  [WS002/MEDIUM] app.db — Database has 9/48 freelist pages (18.8% fragmentation, 36,864 wasted bytes).
     └ Advice: Run 'VACUUM;' or enable 'PRAGMA auto_vacuum = INCREMENTAL;' to reclaim free pages.
  [WS003/HIGH] app.db-wal — WAL file contains 107 frames (442,400 bytes) with 19 dirty page(s).
     └ Advice: Run 'PRAGMA wal_checkpoint(TRUNCATE);' and check for long-running read transactions blocking checkpoints.
  [WS005/HIGH] orders — Query plan step 'SCAN orders' performs a full table scan for query: SELECT * FROM orders WHERE total_cents > 1000
     └ Advice: Add an index on the filter/join columns of 'orders' to convert SCAN into SEARCH USING INDEX.
══════════════════════════════════════════════════════════════════════════════
Summary: 4 finding(s) (HIGH: 3, MEDIUM: 1, LOW: 0)
```

---

## How to Run It

### 1. Install

```bash
git clone https://github.com/Dharmogata/walscope.git
cd walscope
pip install -e .
```

### 2. Inspect a SQLite Database

```bash
# Full binary header, WAL frame, schema, and query-plan inspection
walscope inspect path/to/database.db --query "SELECT * FROM orders WHERE user_id = 42"

# Inspect only the 100-byte binary database header and .db-wal summary
walscope header path/to/database.db

# Export full X-Ray report as JSON or Markdown
walscope inspect path/to/database.db --format markdown

# List all built-in diagnostic rules (WS001 - WS005)
walscope rules
```

### 3. Run the Test Suite

```bash
# Using pytest
pytest -v

# Or using standard library unittest
PYTHONPATH=src python -m unittest discover -s tests -v
```

---

## Planned Work Ahead (TODO & Roadmap)

WalScope has **200+ hours of planned engineering work** detailed in [ROADMAP.md](ROADMAP.md):

- [ ] **Phase 2 (~35h): B-Tree Page & Overflow Cell Binary Inspector (`WS006`–`WS012`)** (parse leaf/interior table and index B-tree page headers `0x0d`, `0x05`, `0x0a`, `0x02`, cell pointer arrays, local vs overflow payload ratios, and per-table page fill factors).
- [ ] **Phase 3 (~40h): Deep `.db-wal` & `.db-shm` Wal-Index Forensics** (validate rolling big/little-endian WAL frame checksums, parse `.db-shm` `wal-index` reader marks `aReadMark[0..4]` to pinpoint which reader slot is blocking `RESTART`/`TRUNCATE` checkpoints, and emit per-page write heatmaps).
- [ ] **Phase 4 (~35h): `dbstat` Virtual Table & Redundant Index Analyzer** (detect duplicate prefix indexes `(a)` vs `(a, b)`, low-selectivity indexes via `sqlite_stat1`, and `WITHOUT ROWID` candidates).
- [ ] **Phase 5 (~40h): Live WAL Tail & Checkpoint Starvation Watchdog (`walscope watch`)** (real-time frame velocity monitor, checkpoint latency tracker, and Litestream/replication lag estimator).
- [ ] **Phase 6 (~35h): SQL Migration Linter, SARIF v2.1.0 Exporter & HTML Page-Map Visualizer**.

See [ROADMAP.md](ROADMAP.md) for the complete specification.

---

## License

Released under the [MIT License](LICENSE).
