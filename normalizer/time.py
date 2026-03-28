
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
        return _normalized_audit(raw_timestamp, default_tz)
    if parser_type == "journal":
        return _normalized_journal(raw_timestamp, default_tz)
    if parser_type == "rfc3164":
        return _normalize_rfc3164(raw_timestamp, default_tz, reference_year)
    if parser_type == "rfc5424":
        return _normalize_rfc5424(raw_timestamp)
    if parser_type in {"evtx", "windows_xml"}:
        return _normalize_wintime(raw_timestamp)
    
    raise ValueError(f"Unsupported parser_type: {parser_type}")

def _normalized_audit(raw_timestamp: str, default_tz: str) -> str:
    """Function used to normalize the audit parsed event timestamp.

    Args:
        raw_timestamp (str): Extracted Unix Epoch time from the audit file
        default_tz (str): Default timezone (UTC)

    Returns:
        str: ISO 8601 Timestamp with milliseconds
    """
    timezone = ZoneInfo(default_tz)
    dt = datetime.fromtimestamp(float(raw_timestamp), tz=timezone)
    
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _normalized_journal(raw_timestamp: str, 
                       default_tz: str ) -> str:
    """Function used to normalize the timestamp for journal log entries

    Args:
        raw_timestamp (str): raw timestamp extracted from event message
        default_tz (str): Default timezone set to the UTC

    Returns:
        str: String formatted ISO8601 timestamp
    """
    value = raw_timestamp.strip()
    
    # timestamp should be formatted correctly
    dt = datetime.fromisoformat(value)
    
    # return the ISO 8061 timestamp
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _normalize_rfc3164(raw_timestamp: str, 
                       default_tz: str, 
                       reference_year: int | None) -> str:
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
    
    # NOTE This section may not be needed if RFC 3164 is configured to support <PRI> data.
    # RFC 3164 does not contain a year. Guess based on month value.
    candidate_year = reference_year if reference_year is not None else now.year
    dt = datetime.strptime(f"{candidate_year} {raw_timestamp}", "%Y %b %d %H:%M:%S")
    dt = dt.replace(tzinfo=tz)
    
    if reference_year is None and dt > now:
        dt =dt.replace(year=dt.year -1)
        
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _normalize_rfc5424(raw_timestamp: str) -> str:
    """Function for processing and normalizing the RFC 5424 timestamps.

    Args:
        raw_timestamp (str): Parser extracted timestamp.
            
    Returns:
        str: ISO 8601 formatted timestamp with milliseconds.
    """
    # Remove the whitespaces from the leading and trailing
    value = raw_timestamp.strip()
    
    # RFC 5424 timestamp is basically correct.
    dt = datetime.fromisoformat(value)
    
    # return the ISO 8061 timestamp
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

def _normalize_wintime(raw_timestamp: str) -> str:
    """Function for processing and normalizing the Windows Event Log timestamps.

    Args:
        raw_timestamp (str): Timestamp extracted from windows event log.

    Returns:
        str: ISO 8061 formatted string from the windows timestamp.
    """
    value = raw_timestamp.strip()
    
    # Remove trailing textual UTC marker
    value = re.sub(r"\s+UTC$", "", value)

    # Trim fractional seconds to 6 digits if needed
    value = re.sub(r"\.(\d{6})\d+", r".\1", value)

    # Extract the datetime object
    dt = datetime.fromisoformat(value)
    
    # return the properly formatted timestamp    
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")