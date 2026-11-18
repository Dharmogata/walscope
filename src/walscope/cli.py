"""Command-line interface for WalScope."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from walscope import __version__
from walscope.analyzer import get_rules, inspect_database
from walscope.binary_parser import (
    InvalidSQLiteHeaderError,
    parse_database_header,
    parse_wal_file,
)
from walscope.formatters import (
    format_header_report,
    format_inspection_report,
    format_rules_catalog,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="walscope",
        description=(
            "WalScope: SQLite binary header, Write-Ahead Log (WAL) frame, "
            "schema index, and query plan X-Ray inspector."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"walscope {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # inspect subcommand
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Run a full binary header, WAL frame, schema, and query-plan inspection.",
    )
    inspect_parser.add_argument(
        "db_path",
        help="Path to the SQLite database file (.db / .sqlite).",
    )
    inspect_parser.add_argument(
        "--query",
        "-q",
        action="append",
        default=[],
        help="SQL query to inspect with EXPLAIN QUERY PLAN (can be passed multiple times).",
    )
    inspect_parser.add_argument(
        "--format",
        "-f",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )
    inspect_parser.add_argument(
        "--min-severity",
        choices=("low", "medium", "high"),
        default="low",
        help="Minimum finding severity to report (default: low).",
    )
    inspect_parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 1 if any diagnostic findings match the severity filter.",
    )

    # header subcommand
    header_parser = subparsers.add_parser(
        "header",
        help="Inspect only the 100-byte SQLite binary header and companion .db-wal header.",
    )
    header_parser.add_argument(
        "db_path",
        help="Path to the SQLite database file.",
    )
    header_parser.add_argument(
        "--format",
        "-f",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text).",
    )

    # rules subcommand
    rules_parser = subparsers.add_parser(
        "rules",
        help="List all built-in WalScope diagnostic rules (WS001-WS005).",
    )
    rules_parser.add_argument(
        "--format",
        "-f",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default: text).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "rules":
            output = format_rules_catalog(get_rules(), fmt=args.format)
            print(output)
            return 0

        if args.command == "header":
            header = parse_database_header(args.db_path)
            wal = parse_wal_file(args.db_path, fallback_page_size=header.page_size)
            output = format_header_report(
                db_path=str(args.db_path),
                header=header,
                wal=wal,
                fmt=args.format,
            )
            print(output)
            return 0

        if args.command == "inspect":
            report = inspect_database(
                db_path=args.db_path,
                queries=args.query,
                min_severity=args.min_severity.upper(),
            )
            output = format_inspection_report(report, fmt=args.format)
            print(output)
            if args.fail_on_findings and report.findings:
                return 1
            return 0

    except (FileNotFoundError, InvalidSQLiteHeaderError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
