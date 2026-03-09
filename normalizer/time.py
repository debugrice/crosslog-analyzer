"""
File: crosslog/normalizer/time.py
Author: Danny Ray
Date: 03/07/2026
Description: Helper functions to update and modify the timestamp.
"""
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
        return None
    if parser_type == "rfc3164":
        return _normalize_rfc3164(raw_timestamp, default_tz, reference_year)
    if parser_type == "rfc5424":
        return _normalize_rfc5424(raw_timestamp, default_tz)
    if parser_type in {"evtx", "windows_xml"}:
        return _normalize_evtx(raw_timestamp)
    
    raise ValueError(f"Unsupported parser_type: {parser_type}")

def _normalize_rfc3164(raw_timestamp: str, 
                       default_tz: str, 
                       reference_year: int | None) -> str:
    """Function for processing and normalizing the RFC 3164 timestamps.

    Args:
        raw_timestamp (str): Parser extracted timestamp.
        default_tz (str): Default time zone.
        reference_year (int | None): Reference year if timestamp is missing data.

    Returns:
        str: ISO 8601 formatted timestamp.
    """
    tz = ZoneInfo(default_tz)
    # Just in case the reference_year is empty
    now = datetime.now(tz)
    # NOTE This section may not be needed if RFC 3164 is configured to support <PRI> data.
    candidate_year = reference_year if reference_year is not None else now.year
    dt = datetime.strptime(f"{candidate_year} {raw_timestamp}", "%Y %b %d %H:%M:%S")
    dt = dt.replace(tzinfo=tz)
    
    if reference_year is None and dt > now:
        dt =dt.replace(year=dt.year -1)
        
    return dt.isoformat(timespec="seconds")

def _normalize_rfc5424(raw_timestamp: str, 
                       default_tz: str) -> str:
    """Function for processing and normalizing the RFC 5424 timestamps.

    Args:
        raw_timestamp (str): Parser extracted timestamp.
        default_tz (str): Default time zone.
    
    Returns:
        str: ISO 8601 formatted timestamp.
    """
    # Remove the whitespaces from the leading and trailing
    value = raw_timestamp.strip()
    
    # Clean up the string to match the expected format
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
        
    # RFC 5424 timestamp is basically correct.
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        # Update the time zone if it's null
        dt = dt.replace(tzinfo=ZoneInfo(default_tz))
    # return the ISO 8061 timestamp
    return dt.isoformat(timespec="seconds")

def _normalize_evtx(raw_timestamp: str) -> str:
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

    # Convert trailing Z to +00:00 for fromisoformat()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    # Extract the datetime object
    dt = datetime.fromisoformat(value)
    
    # return the properly formatted timestamp    
    return dt.isoformat(timespec="seconds")