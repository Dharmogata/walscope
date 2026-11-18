"""SQLite schema, binary storage, WAL backlog, and EXPLAIN QUERY PLAN analyzer."""

from __future__ import annotations

from pathlib import Path
import re
import sqlite3
from typing import Iterable

from walscope.binary_parser import parse_database_header, parse_wal_file
from walscope.models import (
    SEVERITY_ORDER,
    DiagnosticFinding,
    InspectionReport,
    QueryPlanStep,
    RuleDefinition,
    TableStorageStat,
)

BUILT_IN_RULES: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        rule_id="WS001",
        severity="HIGH",
        category="unindexed-foreign-key",
        title="Unindexed Foreign Key Column",
        description=(
            "Foreign key column on a child table lacks a covering index prefix, "
            "causing full table scans on parent row updates or deletes."
        ),
    ),
    RuleDefinition(
        rule_id="WS002",
        severity="MEDIUM",
        category="freelist-fragmentation",
        title="Database Freelist Fragmentation",
        description=(
            "Database freelist page ratio exceeds threshold (>=10% wasted pages), "
            "increasing file size and I/O overhead."
        ),
    ),
    RuleDefinition(
        rule_id="WS003",
        severity="HIGH",
        category="wal-checkpoint-backlog",
        title="WAL Checkpoint Backlog",
        description=(
            "Write-Ahead Log (.db-wal) exceeds frame (>100 frames) or size (>4 MB) "
            "threshold, indicating checkpoint starvation and slower page lookups."
        ),
    ),
    RuleDefinition(
        rule_id="WS004",
        severity="MEDIUM",
        category="table-missing-primary-key",
        title="Table Missing Explicit Primary Key",
        description=(
            "Table lacks an explicit PRIMARY KEY definition, relying only on implicit rowid."
        ),
    ),
    RuleDefinition(
        rule_id="WS005",
        severity="HIGH",
        category="full-table-scan-query",
        title="Full Table Scan in Query Plan",
        description=(
            "EXPLAIN QUERY PLAN reveals a full table SCAN without an index on a queried table."
        ),
    ),
)

_SCAN_TABLE_RE = re.compile(r"\bSCAN\s+(?:TABLE\s+)?([A-Za-z_][A-Za-z0-9_]*)\b", re.IGNORECASE)


def get_rules() -> list[RuleDefinition]:
    """Return all built-in WalScope diagnostic rules."""
    return list(BUILT_IN_RULES)


def _quote_ident(identifier: str) -> str:
    escaped = identifier.replace('"', '""')
    return f'"{escaped}"'


def _open_readonly(db_path: Path) -> sqlite3.Connection:
    # Use standard connect so WAL shared-memory or journal inspection works cleanly in sandboxes
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def inspect_tables(conn: sqlite3.Connection) -> list[TableStorageStat]:
    """Introspect all user tables, indexes, and foreign key coverage in a SQLite database."""
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT name, sql
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()

    stats: list[TableStorageStat] = []
    for row in rows:
        table_name: str = row["name"]
        quoted = _quote_ident(table_name)

        # Columns & primary key check
        col_rows = cur.execute(f"PRAGMA table_info({quoted})").fetchall()
        columns_count = len(col_rows)
        has_pk = any(int(c["pk"]) > 0 for c in col_rows)

        # Row count
        try:
            cnt_row = cur.execute(f"SELECT COUNT(*) AS cnt FROM {quoted}").fetchone()
            row_count = int(cnt_row["cnt"]) if cnt_row else 0
        except sqlite3.Error:
            row_count = 0

        # Gather all index column prefixes for this table
        idx_list = cur.execute(f"PRAGMA index_list({quoted})").fetchall()
        index_count = len(idx_list)
        indexed_prefixes: list[tuple[str, ...]] = []
        for idx in idx_list:
            idx_name = idx["name"]
            idx_cols = cur.execute(f"PRAGMA index_info({_quote_ident(idx_name)})").fetchall()
            ordered_cols = tuple(
                str(ic["name"]).lower()
                for ic in sorted(idx_cols, key=lambda r: int(r["seqno"]))
                if ic["name"] is not None
            )
            if ordered_cols:
                indexed_prefixes.append(ordered_cols)

        # Also include composite PK columns if they form an implicit index
        pk_cols = tuple(
            str(c["name"]).lower()
            for c in sorted(
                (c for c in col_rows if int(c["pk"]) > 0),
                key=lambda r: int(r["pk"]),
            )
        )
        if pk_cols and pk_cols not in indexed_prefixes:
            indexed_prefixes.append(pk_cols)

        # Check foreign keys
        fk_rows = cur.execute(f"PRAGMA foreign_key_list({quoted})").fetchall()
        fks_by_id: dict[int, list[sqlite3.Row]] = {}
        for fk in fk_rows:
            fk_id = int(fk["id"])
            fks_by_id.setdefault(fk_id, []).append(fk)

        missing_fk_columns: list[str] = []
        for _fk_id, fk_group in sorted(fks_by_id.items()):
            ordered_fk = sorted(fk_group, key=lambda r: int(r["seq"]))
            from_cols = tuple(str(r["from"]).lower() for r in ordered_fk)
            ref_table = str(ordered_fk[0]["table"])
            covered = any(
                idx_cols[: len(from_cols)] == from_cols for idx_cols in indexed_prefixes
            )
            if not covered:
                display_cols = ", ".join(str(r["from"]) for r in ordered_fk)
                missing_fk_columns.append(f"{display_cols} -> {ref_table}")

        stats.append(
            TableStorageStat(
                name=table_name,
                row_count=row_count,
                index_count=index_count,
                foreign_keys_missing_index=missing_fk_columns,
                columns_count=columns_count,
                has_primary_key=has_pk,
            )
        )

    return stats


def explain_queries(db_path: str | Path, queries: Iterable[str]) -> list[QueryPlanStep]:
    """Run EXPLAIN QUERY PLAN on one or more SQL queries and detect full table scans."""
    path = Path(db_path)
    steps: list[QueryPlanStep] = []
    conn = _open_readonly(path)
    try:
        cur = conn.cursor()
        for sql in queries:
            cleaned = sql.strip()
            if not cleaned:
                continue
            plan_rows = cur.execute(f"EXPLAIN QUERY PLAN {cleaned}").fetchall()
            for row in plan_rows:
                detail = str(row[3])
                # Detect full table scan: "SCAN <table>" or "SCAN TABLE <table>" without "USING INDEX" / "USING COVERING INDEX"
                upper_detail = detail.upper()
                is_scan = (
                    upper_detail.startswith("SCAN ")
                    and "USING INDEX" not in upper_detail
                    and "USING COVERING INDEX" not in upper_detail
                    and "SCAN SUBQUERY" not in upper_detail
                    and "SCAN CONSTANT" not in upper_detail
                )
                steps.append(
                    QueryPlanStep(
                        select_id=int(row[0]),
                        order=int(row[1]),
                        from_idx=int(row[2]),
                        detail=detail,
                        is_full_scan=is_scan,
                        query=cleaned,
                    )
                )
    finally:
        conn.close()
    return steps


def inspect_database(
    db_path: str | Path,
    queries: Iterable[str] | None = None,
    min_severity: str = "LOW",
    fragmentation_threshold: float = 0.10,
    wal_frame_threshold: int = 100,
    wal_bytes_threshold: int = 4 * 1024 * 1024,
) -> InspectionReport:
    """Perform a full binary, WAL, schema, and query-plan X-Ray inspection on a SQLite database."""
    path = Path(db_path)
    header = parse_database_header(path)
    wal = parse_wal_file(path, fallback_page_size=header.page_size)

    conn = _open_readonly(path)
    try:
        tables = inspect_tables(conn)
    finally:
        conn.close()

    query_plans = explain_queries(path, queries or [])

    findings: list[DiagnosticFinding] = []

    # WS001: Unindexed Foreign Keys
    for tbl in tables:
        for missing_fk in tbl.foreign_keys_missing_index:
            fk_cols = missing_fk.split(" -> ")[0]
            findings.append(
                DiagnosticFinding(
                    rule_id="WS001",
                    severity="HIGH",
                    category="unindexed-foreign-key",
                    target=f"{tbl.name}({fk_cols})",
                    message=(
                        f"Foreign key '{missing_fk}' on table '{tbl.name}' lacks a covering index prefix."
                    ),
                    advice=(
                        f"Create an index: CREATE INDEX idx_{tbl.name}_{fk_cols.replace(', ', '_')} "
                        f"ON {tbl.name} ({fk_cols});"
                    ),
                )
            )

    # WS002: Freelist Fragmentation
    if header.freelist_pages > 0 and header.fragmentation_ratio >= fragmentation_threshold:
        pct = header.fragmentation_ratio * 100.0
        findings.append(
            DiagnosticFinding(
                rule_id="WS002",
                severity="MEDIUM",
                category="freelist-fragmentation",
                target=path.name,
                message=(
                    f"Database has {header.freelist_pages}/{header.page_count} freelist pages "
                    f"({pct:.1f}% fragmentation, {header.wasted_bytes:,} wasted bytes)."
                ),
                advice="Run 'VACUUM;' or enable 'PRAGMA auto_vacuum = INCREMENTAL;' to reclaim free pages.",
            )
        )

    # WS003: WAL Checkpoint Backlog
    if wal.exists and (
        wal.frame_count > wal_frame_threshold or wal.file_size_bytes > wal_bytes_threshold
    ):
        findings.append(
            DiagnosticFinding(
                rule_id="WS003",
                severity="HIGH",
                category="wal-checkpoint-backlog",
                target=f"{path.name}-wal",
                message=(
                    f"WAL file contains {wal.frame_count} frames ({wal.file_size_bytes:,} bytes) "
                    f"with {wal.uncheckpointed_pages} dirty page(s)."
                ),
                advice=(
                    "Run 'PRAGMA wal_checkpoint(TRUNCATE);' and check for long-running read "
                    "transactions blocking checkpoints."
                ),
            )
        )

    # WS004: Table Missing Primary Key
    for tbl in tables:
        if not tbl.has_primary_key:
            findings.append(
                DiagnosticFinding(
                    rule_id="WS004",
                    severity="MEDIUM",
                    category="table-missing-primary-key",
                    target=tbl.name,
                    message=f"Table '{tbl.name}' has no explicit PRIMARY KEY column.",
                    advice=(
                        f"Define an explicit PRIMARY KEY on '{tbl.name}' to enforce entity identity "
                        "and stable indexing."
                    ),
                )
            )

    # WS005: Full Table Scan in Query Plan
    for step in query_plans:
        if step.is_full_scan:
            match = _SCAN_TABLE_RE.search(step.detail)
            scanned_table = match.group(1) if match else step.detail
            findings.append(
                DiagnosticFinding(
                    rule_id="WS005",
                    severity="HIGH",
                    category="full-table-scan-query",
                    target=scanned_table,
                    message=(
                        f"Query plan step '{step.detail}' performs a full table scan for query: {step.query}"
                    ),
                    advice=(
                        f"Add an index on the filter/join columns of '{scanned_table}' to convert "
                        "SCAN into SEARCH USING INDEX."
                    ),
                )
            )

    min_rank = SEVERITY_ORDER.get(min_severity.upper(), 1)
    filtered_findings = [
        f for f in findings if SEVERITY_ORDER.get(f.severity.upper(), 0) >= min_rank
    ]

    return InspectionReport(
        db_path=str(path),
        header=header,
        wal=wal,
        tables=tables,
        query_plans=query_plans,
        findings=filtered_findings,
    )
