"""
File: crosslog/parsers/rfc5424.py
Author: Danny Ray
Date: 03/07/2026
Description: RFC5424 Parser used to extract standardized syslog protocol.
"""
import re

from models.parsed_event import ParsedEvent
from parsers.baseline_parser import BaseLineParser
from syslog_rfc5424_parser import SyslogMessage

class RFC5424Parser(BaseLineParser):
    """Implementation of the RFC 5424 file parser

    Args:
        BaseLineParser (_type_): Parent class which implements the parse_file method.

    Returns:
        _type_: ParsedEvent message
    """
    parser_type = "rfc5424"
    
    def parse_line(self, 
                   line: str, 
                   source: str, 
                   line_number: int | None = None) -> ParsedEvent:
        """Overridden method to extract and parse each text line from the file.

        Args:
            line (str): Line of data from the text file.
            source (str): File providing the data.
            line_number (int | None, optional): Line number. Defaults to None.

        Returns:
            ParsedEvent: Parsed object from the provided string.
        """
        # Reference call to the syslog-rfc5424-parser import.
        msg = SyslogMessage.parse(line)

        facility = msg.facility
        severity = msg.severity

        pid = getattr(msg, "procid", None)
        if isinstance(pid, str) and pid.isdigit():
            pid = int(pid)

        structured_data = getattr(msg, "structured_data", None)

        return ParsedEvent(
            source=source,
            parser_type=self.parser_type,
            timestamp=str(getattr(msg, "timestamp", None)) if getattr(msg, "timestamp", None) is not None else None,
            host=_nil_to_none(getattr(msg, "hostname", None)),
            program=_nil_to_none(getattr(msg, "appname", None)),
            pid=pid,
            message=_nil_to_empty(getattr(msg, "msg", None)),
            severity=severity,
            facility=facility,
            event_id=None,
            fields={
                "version": getattr(msg, "version", None),
                "msgid": _nil_to_none(getattr(msg, "msgid", None)),
                "structured_data": structured_data,
                "line_number": line_number,
            },
        )


def _nil_to_none(value):
    """Private function used to clean up the formatting. Replace missing values with None.

    Args:
        value (str): string to be modified.

    Returns:
        str : Modified string.
    """
    if value in {None, "-", ""}:
        return None
    return value

def _nil_to_empty(value):
    """Private function used to clean up the formatting. Replace None or "-" with empty string.

    Args:
        value (str): message line from RFC 5424

    Returns:
        str: Modified string.
    """
    if value in {None, "-"}:
        return ""
    return str(value)