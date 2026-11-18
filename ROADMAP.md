# WalScope Engineering Roadmap (200+ Hours)

This roadmap details the planned multi-phase evolution of **WalScope** from a binary SQLite header, `.db-wal` frame summary, schema index, and `EXPLAIN QUERY PLAN` inspector into a full B-tree page forensics toolkit, `.db-shm` lock analyzer, and real-time WAL checkpoint watchdog.

---

## Phase 1: Binary Header, WAL Frame Summary, Schema & Query-Plan X-Ray (Completed - v0.1.0)
- [x] Core data models for binary headers, WAL summaries, table storage stats, query plan steps, and diagnostic findings (`models.py`).
- [x] Pure-Python 100-byte SQLite3 binary header parser and 32-byte `.db-wal` + 24-byte frame header parser (`binary_parser.py`).
- [x] Built-in rules `WS001` (unindexed foreign key), `WS002` (freelist fragmentation), `WS003` (WAL checkpoint backlog), `WS004` (table missing primary key), and `WS005` (`EXPLAIN QUERY PLAN` full table scan).
- [x] CLI (`inspect`, `header`, `rules`) with `text`, `json`, and `markdown` output formatters.

---

## Phase 2: B-Tree Page & Overflow Cell Binary Inspector (`WS006`–`WS012`) (~35 Hours)
- [ ] **B-Tree Page Type Classifier (`btree_parser.py`):** Walk raw database pages and decode 8/12-byte B-tree page headers (`0x02` index interior, `0x05` table interior, `0x0a` index leaf, `0x0d` table leaf), cell counts, cell content area offsets, and fragmented free bytes.
- [ ] **Rule `WS006` (Overflow Page Chain Amplification):** Detect tables where large `TEXT`/`BLOB` columns spill into long linked lists of overflow pages (`U > P - 35`), degrading sequential scans.
- [ ] **Rule `WS007` (Freelist Trunk vs Leaf Chain Discrepancy):** Traverse the freelist trunk page (`offset 32`) and verify that every freelist trunk and leaf page pointer stays within bounds and matches `freelist_pages`.

---

## Phase 3: Deep `.db-wal` Checksum Verifier & `.db-shm` Reader Lock Forensics (~40 Hours)
- [ ] **Cumulative WAL Frame Checksum Validator:** Recompute SQLite's native 64-bit cumulative checksum (`s0`, `s1`) across the 32-byte WAL header and each 24-byte frame header + page payload to pinpoint the exact frame where a WAL commit ends or was torn.
- [ ] **Shared-Memory (`.db-shm`) `wal-index` Parser:** Parse the first 136 bytes of the `.db-shm` `WalIndexHdr` and `WalCkptInfo` structures (`nBackfill`, `aReadMark[0..4]`, `aLock[0..7]`) to identify stale reader transactions preventing WAL truncation.
- [ ] **Per-Page WAL Write Heatmap (`walscope wal-heatmap`):** Rank database page numbers (and map them back to owning B-tree tables/indexes) by how frequently they are rewritten inside `.db-wal`.

---

## Phase 4: Index Redundancy, `sqlite_stat1` & `dbstat` Storage Analyzer (~35 Hours)
- [ ] **Rule `WS008` (Redundant Prefix Index):** Flag indexes whose column list `(a, b)` already covers a narrower non-unique index `(a)` on the same table and collation order.
- [ ] **Rule `WS009` (`AUTOINCREMENT` `sqlite_sequence` Overhead):** Detect unnecessary `INTEGER PRIMARY KEY AUTOINCREMENT` declarations that trigger extra writes to `sqlite_sequence` on every insert.
- [ ] **Virtual Table `dbstat` Integration:** When the local SQLite build includes `SQLITE_ENABLE_DBSTAT_VTAB`, compute exact per-table and per-index byte footprints and leaf page fill percentages.

---

## Phase 5: Live WAL Tail & Checkpoint Starvation Watchdog (`walscope watch`) (~40 Hours)
- [ ] **Live Frame Velocity & Salt Rotation Monitor:** Poll `.db-wal` and `.db-shm` at configurable intervals without acquiring database locks, tracking frames/sec, `salt_1` increments (checkpoint resets), and high-water WAL file size.
- [ ] **PRAGMA Production Readiness Audit (`WS010`–`WS015`):** Audit runtime pragmas (`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout`, `foreign_keys=ON`, `temp_store=MEMORY`, `mmap_size`) against recommended production SQLite profiles.

---

## Phase 6: SQL Query Log Analyzer, SARIF v2.1.0 & Interactive Page Map (~35 Hours)
- [ ] **Batch SQL Query Workload Profiler (`walscope explain-file queries.sql`):** Parse multi-statement `.sql` files or application query logs, run `EXPLAIN QUERY PLAN` on every statement, and rank missing indexes by how many queries they accelerate.
- [ ] **SARIF v2.1.0 Output & SVG Binary Page Map Exporter (`walscope page-map app.db -o map.svg`)**.
