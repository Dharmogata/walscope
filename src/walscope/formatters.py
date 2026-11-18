"""Text, JSON, and Markdown formatters for WalScope inspection reports, headers, and rules."""

from __future__ import annotations

import json
from typing import Iterable

from walscope.models import DatabaseHeaderInfo, InspectionReport, RuleDefinition, WalFileSummary


def format_header_report(
    db_path: str,
    header: DatabaseHeaderInfo,
    wal: WalFileSummary,
    fmt: str = "text",
) -> str:
    """Format binary header and WAL summary as text or json."""
    if fmt == "json":
        payload = {
            "db_path": db_path,
            "header": header.to_dict(),
            "wal": wal.to_dict(),
        }
        return json.dumps(payload, indent=2)

    frag_pct = header.fragmentation_ratio * 100.0
    journal_mode = "WAL (2/2)" if header.wal_mode else f"Legacy ({header.write_version}/{header.read_version})"
    lines = [
        f"WalScope Binary Header X-Ray ({db_path})",
        "─" * 78,
        f"  Page Size          : {header.page_size:,} bytes",
        f"  Total Pages        : {header.page_count:,} ({header.total_size_bytes:,} bytes)",
        f"  Freelist Pages     : {header.freelist_pages:,} ({frag_pct:.1f}% fragmentation)",
        f"  Journal Versions   : {journal_mode}",
        f"  Text Encoding      : {header.text_encoding}",
        f"  Schema Format      : {header.schema_format} (cookie: {header.schema_cookie})",
        f"  User Version       : {header.user_version} (app_id: 0x{header.application_id:08x})",
    ]
    if wal.exists:
        lines.extend(
            [
                "─" * 78,
                f"  WAL File Status    : PRESENT ({wal.file_size_bytes:,} bytes)",
                f"  WAL Frames         : {wal.frame_count:,} ({wal.uncheckpointed_pages:,} dirty pages)",
                f"  WAL Salts          : 0x{wal.salt_1:08x} / 0x{wal.salt_2:08x}",
                f"  Checkpoint Pressure: {wal.checkpoint_pressure}",
            ]
        )
    else:
        lines.extend(
            [
                "─" * 78,
                "  WAL File Status    : NOT PRESENT (0 frames)",
            ]
        )
    lines.append("─" * 78)
    return "\n".join(lines)


def format_inspection_report(report: InspectionReport, fmt: str = "text") -> str:
    """Format a complete InspectionReport as text, json, or markdown."""
    if fmt == "json":
        return json.dumps(report.to_dict(), indent=2)

    if fmt == "markdown":
        return _format_inspection_markdown(report)

    header = report.header
    wal = report.wal
    frag_pct = header.fragmentation_ratio * 100.0
    mode_str = "WAL" if header.wal_mode else "DELETE/TRUNCATE"

    lines = [
        f"WalScope X-Ray Report ({report.db_path})",
        "═" * 78,
        "[Binary Header & Storage]",
        f"  Page Size: {header.page_size:,} B | Pages: {header.page_count:,} "
        f"({header.total_size_bytes:,} B) | Freelist: {header.freelist_pages:,} ({frag_pct:.1f}%)",
        f"  Encoding : {header.text_encoding} | Mode: {mode_str} | "
        f"Schema Format: {header.schema_format} | User Version: {header.user_version}",
        "",
        "[Write-Ahead Log (.db-wal)]",
    ]
    if wal.exists:
        lines.append(
            f"  Status: PRESENT ({wal.file_size_bytes:,} B) | Frames: {wal.frame_count:,} | "
            f"Dirty Pages: {wal.uncheckpointed_pages:,} | Pressure: {wal.checkpoint_pressure}"
        )
    else:
        lines.append("  Status: NOT PRESENT (checkpointed or non-WAL mode)")

    lines.extend(["", f"[Schema Tables ({len(report.tables)})]"])
    if report.tables:
        for tbl in report.tables:
            pk_badge = "PK:YES" if tbl.has_primary_key else "PK:NO "
            fk_warn = (
                f" | Unindexed FK: {', '.join(tbl.foreign_keys_missing_index)}"
                if tbl.foreign_keys_missing_index
                else ""
            )
            lines.append(
                f"  - {tbl.name:<20} rows={tbl.row_count:<6} cols={tbl.columns_count:<3} "
                f"indexes={tbl.index_count:<3} {pk_badge}{fk_warn}"
            )
    else:
        lines.append("  (no user tables found)")

    if report.query_plans:
        lines.extend(["", f"[Query Plan X-Ray ({len(report.query_plans)} step(s))]"])
        for step in report.query_plans:
            flag = "SCAN!" if step.is_full_scan else "OK   "
            lines.append(f"  [{flag}] {step.detail}  (sql: {step.query})")

    lines.extend(["", f"[Diagnostic Findings ({len(report.findings)})]"])
    if report.findings:
        for finding in report.findings:
            lines.append(
                f"  [{finding.rule_id}/{finding.severity}] {finding.target} — {finding.message}"
            )
            lines.append(f"     └ Advice: {finding.advice}")
    else:
        lines.append("  No diagnostic issues detected.")

    lines.append("═" * 78)
    high_cnt = sum(1 for f in report.findings if f.severity == "HIGH")
    med_cnt = sum(1 for f in report.findings if f.severity == "MEDIUM")
    low_cnt = sum(1 for f in report.findings if f.severity == "LOW")
    lines.append(
        f"Summary: {len(report.findings)} finding(s) "
        f"(HIGH: {high_cnt}, MEDIUM: {med_cnt}, LOW: {low_cnt})"
    )
    return "\n".join(lines)


def _format_inspection_markdown(report: InspectionReport) -> str:
    header = report.header
    wal = report.wal
    frag_pct = header.fragmentation_ratio * 100.0
    lines = [
        f"# WalScope X-Ray Report: `{report.db_path}`",
        "",
        "## Binary Header & WAL Summary",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| Page Size | `{header.page_size:,} B` |",
        f"| Total Pages | `{header.page_count:,}` (`{header.total_size_bytes:,} B`) |",
        f"| Freelist Pages | `{header.freelist_pages:,}` (`{frag_pct:.1f}%`) |",
        f"| Text Encoding | `{header.text_encoding}` |",
        f"| WAL Mode | `{header.wal_mode}` |",
        f"| WAL Frames | `{wal.frame_count:,}` (`{wal.uncheckpointed_pages:,}` dirty pages, `{wal.checkpoint_pressure}` pressure) |",
        "",
        "## Diagnostic Findings",
        "",
    ]
    if not report.findings:
        lines.append("No diagnostic findings detected.")
    else:
        lines.extend(
            [
                "| Rule | Severity | Target | Message | Advice |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in report.findings:
            lines.append(
                f"| `{f.rule_id}` | **{f.severity}** | `{f.target}` | {f.message} | {f.advice} |"
            )
    return "\n".join(lines)


def format_rules_catalog(rules: Iterable[RuleDefinition], fmt: str = "text") -> str:
    """Format the built-in diagnostic rules catalog as text, json, or markdown."""
    rule_list = list(rules)
    if fmt == "json":
        return json.dumps([r.to_dict() for r in rule_list], indent=2)

    if fmt == "markdown":
        lines = [
            "# WalScope Diagnostic Rules",
            "",
            "| Rule ID | Severity | Category | Title | Description |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in rule_list:
            lines.append(
                f"| `{r.rule_id}` | **{r.severity}** | `{r.category}` | {r.title} | {r.description} |"
            )
        return "\n".join(lines)

    lines = [
        "WalScope Diagnostic Rules Catalog",
        "─" * 78,
    ]
    for r in rule_list:
        lines.append(f"  {r.rule_id} [{r.severity:<6}] ({r.category}) - {r.title}")
        lines.append(f"    {r.description}")
    lines.append("─" * 78)
    return "\n".join(lines)
