"""Core data models for WalScope SQLite binary, WAL, schema, and query plan inspection."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


@dataclass(frozen=True)
class DatabaseHeaderInfo:
    """Parsed 100-byte SQLite3 binary database header fields."""

    page_size: int
    page_count: int
    freelist_pages: int
    schema_format: int
    write_version: int
    read_version: int
    text_encoding: str
    user_version: int
    application_id: int
    wal_mode: bool
    fragmentation_ratio: float
    first_freelist_trunk_page: int = 0
    schema_cookie: int = 0

    @property
    def fragmentation_Ratio(self) -> float:
        """Alias for fragmentation_ratio."""
        return self.fragmentation_ratio

    @property
    def total_size_bytes(self) -> int:
        return self.page_size * self.page_count

    @property
    def wasted_bytes(self) -> int:
        return self.page_size * self.freelist_pages

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["total_size_bytes"] = self.total_size_bytes
        data["wasted_bytes"] = self.wasted_bytes
        return data


@dataclass(frozen=True)
class WalFileSummary:
    """Parsed SQLite Write-Ahead Log (.db-wal) binary header and frame summary."""

    exists: bool
    file_size_bytes: int
    frame_count: int
    salt_1: int
    salt_2: int
    uncheckpointed_pages: int
    checkpoint_pressure: str
    magic: int = 0
    format_version: int = 0
    page_size: int = 0
    checkpoint_seq: int = 0
    dirty_page_numbers: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TableStorageStat:
    """Storage and index metadata for a user table in the SQLite schema."""

    name: str
    row_count: int
    index_count: int
    foreign_keys_missing_index: list[str]
    columns_count: int
    has_primary_key: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DiagnosticFinding:
    """A schema, binary storage, WAL, or query-plan diagnostic finding."""

    rule_id: str
    severity: str
    category: str
    target: str
    message: str
    advice: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class QueryPlanStep:
    """A single node from SQLite EXPLAIN QUERY PLAN."""

    select_id: int
    order: int
    from_idx: int
    detail: str
    is_full_scan: bool
    query: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuleDefinition:
    """Metadata describing a built-in WalScope diagnostic rule."""

    rule_id: str
    severity: str
    category: str
    title: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InspectionReport:
    """Complete X-Ray inspection report for a SQLite database file."""

    db_path: str
    header: DatabaseHeaderInfo
    wal: WalFileSummary
    tables: list[TableStorageStat] = field(default_factory=list)
    query_plans: list[QueryPlanStep] = field(default_factory=list)
    findings: list[DiagnosticFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "db_path": self.db_path,
            "header": self.header.to_dict(),
            "wal": self.wal.to_dict(),
            "tables": [t.to_dict() for t in self.tables],
            "query_plans": [q.to_dict() for q in self.query_plans],
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total_tables": len(self.tables),
                "total_findings": len(self.findings),
                "high_severity": sum(1 for f in self.findings if f.severity == "HIGH"),
                "medium_severity": sum(1 for f in self.findings if f.severity == "MEDIUM"),
                "low_severity": sum(1 for f in self.findings if f.severity == "LOW"),
            },
        }
