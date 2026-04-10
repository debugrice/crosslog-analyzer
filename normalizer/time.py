
import re
from datetime import datetime
from zoneinfo import ZoneInfo

def normalize_timestamp( raw_timestamp: str | None,
                        parser_type: str,
                        default_tz: str = "UTC",
                        reference_year: int | None = None,
                        ) -> str | None:
    """Primary timestamp normalizing function. 

    Args:
        raw_timestamp (str | None): Extracted timestamp from the log.
        parser_type (str): Type of parser extracting the message.
        default_tz (str, optional): Default timezone value. Defaults to "UTC".
        reference_year (int | None, optional): Default reference year. Defaults to None.

    Raises:
        ValueError: Unsupported parser will throw this error.

    Returns:
        str | None: ISO formatted timestamp
    """
    if not raw_timestamp:
        return 
    if parser_type == "auditd":
        return _normalize_audit(raw_timestamp, default_tz)
    if parser_type == "journal":
        return _normalize_journal(raw_timestamp, default_tz)
    if parser_type == "rfc3164":
        return _normalize_rfc3164(raw_timestamp, default_tz, reference_year)
    if parser_type == "rfc5424":
        return _normalize_rfc5424(raw_timestamp, default_tz)
    if parser_type in {"evtx", "windows_xml"}:
        return _normalize_wintime(raw_timestamp, default_tz)

    raise ValueError(f"Unsupported parser_type: {parser_type}")
    

def _normalize_audit(raw_timestamp: str, default_tz: str) -> str:
    """Function used to normalize the audit parsed event timestamp.

    Args:
        raw_timestamp (str): Extracted Unix Epoch time from the audit file
        default_tz (str): Default timezone (UTC)

    Returns:
        str: ISO 8601 Timestamp with milliseconds
    """
    ts = raw_timestamp.strip()

    # audit(1710873452.123:420) style
    match = re.search(r"(\d+(?:\.\d+)?)", ts)
    if not match:
        raise ValueError(f"Invalid audit timestamp: {raw_timestamp!r}")

    epoch_value = float(match.group(1))
    tzinfo = ZoneInfo(default_tz)
    dt = datetime.fromtimestamp(epoch_value, tz=tzinfo)

    return dt.isoformat(timespec="microseconds")

def _normalize_journal(raw_timestamp: str, default_tz: str) -> str:
    """Function used to normalize the timestamp for journal log entries

    Args:
        raw_timestamp (str): raw timestamp extracted from event message
        default_tz (str): Default timezone set to the UTC

    Returns:
        str: String formatted ISO8601 timestamp
    """
    return _parse_iso8601(raw_timestamp, default_tz)

def _normalize_rfc3164( raw_timestamp: str, default_tz: str, reference_year: int | None = None,
                       ) -> str:
    """Function for processing and normalizing the RFC 3164 timestamps.

    Args:
        raw_timestamp (str): Parser extracted timestamp.
        default_tz (str): Default time zone.
        reference_year (int | None): Reference year if timestamp is missing data.

    Returns:
        str: ISO 8601 formatted timestamp with milliseconds.
    """
    tz = ZoneInfo(default_tz)
    # Just in case the reference_year is empty
    now = datetime.now(tz)
    
    candidate_year = reference_year if reference_year is not None else now.year
    dt = datetime.strptime(f"{candidate_year} {raw_timestamp}", "%Y %b %d %H:%M:%S")
    dt = dt.replace(tzinfo=tz)
    
    if reference_year is None and dt > now:
        dt =dt.replace(year=dt.year -1)
    
    return dt.isoformat(timespec="microseconds")

def _normalize_rfc5424(raw_timestamp: str, default_tz: str) -> str:
    """Function for processing and normalizing the RFC 5424 timestamps.

    Args:
        raw_timestamp (str): Parser extracted timestamp.
            
    Returns:
        str: ISO 8601 formatted timestamp with milliseconds.
    """
    return _parse_iso8601(raw_timestamp, default_tz)

def _normalize_wintime(raw_timestamp: str, default_tz: str) -> str:
    """Function for processing and normalizing the Windows Event Log timestamps.

    Args:
        raw_timestamp (str): Timestamp extracted from windows event log.

    Returns:
        str: ISO 8061 formatted string from the windows timestamp.
    """
    return _parse_iso8601(raw_timestamp, default_tz)

def _parse_iso8601(ts: str, default_tz: str = "UTC") -> str:
    """Normalize ISO8601 timestamp to timezone-aware string with 6-digit microseconds."""
    ts = ts.strip()

    # Remove textual UTC marker like " UTC"
    ts = re.sub(r"\s+UTC$", "", ts)

    # Convert trailing Z to explicit offset
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"

    # Match:
    # 2020-09-09T13:18:25
    # 2020-09-09T13:18:25.37712
    # 2020-09-09T13:18:25+00:00
    # 2020-09-09T13:18:25.37712+00:00
    match = re.fullmatch(
        r"(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        r"(?:\.(?P<fraction>\d+))?"
        r"(?P<tz>[+-]\d{2}:\d{2})?",
        ts,
    )

    if not match:
        raise ValueError(f"Invalid ISO8601 timestamp: {ts!r}")

    base = match.group("base")
    fraction = match.group("fraction")
    tz_part = match.group("tz")

    # Normalize fraction to exactly 6 digits
    if fraction is None:
        fraction = "000000"
    else:
        fraction = fraction[:6].ljust(6, "0")

    normalized = f"{base}.{fraction}"
    if tz_part:
        normalized += tz_part

    dt = datetime.fromisoformat(normalized)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(default_tz))

    return dt.isoformat(timespec="microseconds")