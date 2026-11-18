"""Pure-Python binary parsers for the 100-byte SQLite3 header and 32-byte WAL frame stream."""

from __future__ import annotations

from pathlib import Path
import struct

from walscope.models import DatabaseHeaderInfo, WalFileSummary

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGIC_BIG_ENDIAN = 0x377F0683
WAL_MAGIC_LITTLE_ENDIAN = 0x377F0682
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24

TEXT_ENCODINGS: dict[int, str] = {
    1: "UTF-8",
    2: "UTF-16le",
    3: "UTF-16be",
}


class InvalidSQLiteHeaderError(ValueError):
    """Raised when a file does not start with a valid 100-byte SQLite3 header."""


def parse_database_header(db_path: str | Path) -> DatabaseHeaderInfo:
    """Parse the 100-byte SQLite3 database header using struct.unpack."""
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Database file not found: {path}")

    file_size = path.stat().st_size
    with path.open("rb") as fh:
        raw = fh.read(100)

    if len(raw) < 100 or raw[:16] != SQLITE_MAGIC:
        raise InvalidSQLiteHeaderError(
            f"File '{path}' does not contain a valid 100-byte 'SQLite format 3\\x00' header."
        )

    raw_page_size, write_ver, read_ver, _reserved, _max_frag, _min_frag, _leaf_frag = struct.unpack(
        ">HBBBBBB", raw[16:24]
    )
    page_size = 65536 if raw_page_size == 1 else raw_page_size

    (
        _file_change_counter,
        header_page_count,
        first_freelist_trunk,
        freelist_pages,
        schema_cookie,
        schema_format,
        _default_cache_size,
        _largest_root_btree,
        encoding_code,
        user_version,
        _incremental_vacuum,
        application_id,
    ) = struct.unpack(">IIIIIIIIIIII", raw[24:72])

    # If header page_count is 0 (older SQLite or uninitialized), infer from file size
    page_count = header_page_count
    if page_count == 0 and page_size > 0:
        page_count = file_size // page_size

    text_encoding = TEXT_ENCODINGS.get(encoding_code, f"UNKNOWN({encoding_code})")
    wal_mode = write_ver == 2 or read_ver == 2
    fragmentation_ratio = (
        round(freelist_pages / page_count, 4) if page_count > 0 else 0.0
    )

    return DatabaseHeaderInfo(
        page_size=page_size,
        page_count=page_count,
        freelist_pages=freelist_pages,
        schema_format=schema_format,
        write_version=write_ver,
        read_version=read_ver,
        text_encoding=text_encoding,
        user_version=user_version,
        application_id=application_id,
        wal_mode=wal_mode,
        fragmentation_ratio=fragmentation_ratio,
        first_freelist_trunk_page=first_freelist_trunk,
        schema_cookie=schema_cookie,
    )


def parse_wal_file(db_path: str | Path, fallback_page_size: int = 4096) -> WalFileSummary:
    """Parse a companion .db-wal file (32-byte header + 24-byte frame headers)."""
    path = Path(db_path)
    wal_path = Path(f"{path}-wal")
    if not wal_path.is_file():
        return WalFileSummary(
            exists=False,
            file_size_bytes=0,
            frame_count=0,
            salt_1=0,
            salt_2=0,
            uncheckpointed_pages=0,
            checkpoint_pressure="NONE",
        )

    file_size = wal_path.stat().st_size
    if file_size < WAL_HEADER_SIZE:
        return WalFileSummary(
            exists=True,
            file_size_bytes=file_size,
            frame_count=0,
            salt_1=0,
            salt_2=0,
            uncheckpointed_pages=0,
            checkpoint_pressure="LOW",
        )

    with wal_path.open("rb") as fh:
        header_bytes = fh.read(WAL_HEADER_SIZE)
        (
            magic,
            format_version,
            wal_page_size,
            checkpoint_seq,
            salt_1,
            salt_2,
            _checksum_1,
            _checksum_2,
        ) = struct.unpack(">IIIIIIII", header_bytes)

        if magic not in (WAL_MAGIC_BIG_ENDIAN, WAL_MAGIC_LITTLE_ENDIAN):
            raise InvalidSQLiteHeaderError(
                f"Invalid WAL magic number 0x{magic:08x} in '{wal_path}'"
            )

        effective_page_size = wal_page_size if wal_page_size > 0 else fallback_page_size
        frame_stride = WAL_FRAME_HEADER_SIZE + effective_page_size
        remaining_bytes = file_size - WAL_HEADER_SIZE
        frame_count = remaining_bytes // frame_stride if frame_stride > 0 else 0

        dirty_pages: set[int] = set()
        for idx in range(frame_count):
            offset = WAL_HEADER_SIZE + idx * frame_stride
            fh.seek(offset)
            frame_hdr = fh.read(WAL_FRAME_HEADER_SIZE)
            if len(frame_hdr) < WAL_FRAME_HEADER_SIZE:
                break
            page_no, _db_size_after_commit, f_salt_1, f_salt_2, _csum1, _csum2 = struct.unpack(
                ">IIIIII", frame_hdr
            )
            # Only frames matching the current WAL header salts belong to the active WAL generation
            if f_salt_1 == salt_1 and f_salt_2 == salt_2 and page_no > 0:
                dirty_pages.add(page_no)

    if frame_count > 100 or file_size > 4 * 1024 * 1024:
        pressure = "HIGH"
    elif frame_count > 25 or file_size > 1024 * 1024:
        pressure = "MEDIUM"
    elif frame_count > 0:
        pressure = "LOW"
    else:
        pressure = "NONE"

    return WalFileSummary(
        exists=True,
        file_size_bytes=file_size,
        frame_count=frame_count,
        salt_1=salt_1,
        salt_2=salt_2,
        uncheckpointed_pages=len(dirty_pages),
        checkpoint_pressure=pressure,
        magic=magic,
        format_version=format_version,
        page_size=effective_page_size,
        checkpoint_seq=checkpoint_seq,
        dirty_page_numbers=sorted(dirty_pages),
    )
