"""RFC 3339 UTC timestamps with exactly millisecond precision."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .errors import malformed

_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$"
)


def parse_ts(value: object, field: str = "time") -> int:
    """Parse RFC3339-millisecond UTC -> integer milliseconds since epoch."""
    if not isinstance(value, str):
        raise malformed(f"{field} must be an RFC3339 string")
    m = _TS_RE.match(value)
    if not m:
        raise malformed(f"{field} must be RFC3339 with millisecond precision")
    y, mo, d, h, mi, s, ms = (int(g) for g in m.groups())
    try:
        dt = datetime(y, mo, d, h, mi, s, ms * 1000, tzinfo=timezone.utc)
    except ValueError as e:
        raise malformed(f"{field} is not a real instant: {e}") from e
    return int(dt.timestamp() * 1000)


def fmt_ts(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def add_seconds(ms: int, seconds: int) -> int:
    return ms + seconds * 1000
