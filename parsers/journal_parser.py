import json
import re
from datetime import datetime, timezone
from typing import Optional

from models.parsed_event import ParsedEvent
from parsers.baseline_parser import BaseLineParser

# Default journal log output
JOURNAL_DEFAULT_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\[]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Journal log output if use extracts with ISO-8601 timestamps
JOURNAL_SHORT_ISO_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\[]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

class JournalParser(BaseLineParser):
    """Parser for journalctl output.
    """

    parser_type = "journal"

    def parse_line( self, line: str, 
                   source: Optional[str] = None,
                   line_number: Optional[int] = None, ) -> Optional[ParsedEvent]:
        """Subclass specific method to extract and parse JSON from the line

        Args:
            line (str): Line of string data to parse as JSON
            source_name (Optional[str], optional): Source file path. Defaults to None.
            line_number (Optional[int], optional): Line number from the source file path. Defaults to None.

        Returns:
            Optional[ParsedEvent]: Returns a ParsedEvent object
        """
        line = line.strip()
        if not line:
            return None

        event = self._parse_json_line(line)

        if event:
            if source is not None:
                event.source = source
            if line_number is not None:
                event.fields["line_number"] = line_number
            return event

        # Attempt to parse the string an ISO 8601 timestamp
        event = self._parse_short_iso_line(line)
        if event:
            if source is not None:
                event.source = source
            if line_number is not None:
                event.fields["line_number"] = line_number
            return event
        
        # Attempt to parse the string as standard RFC3164 timestamp
        event = self._parse_default_line(line)
        if event:
            if source is not None:
                event.source = source
            if line_number is not None:
                event.fields["line_number"] = line_number
            return event

        return None

    def _parse_json_line(self, line: str) -> Optional[ParsedEvent]:
        """Private method used used to parse a line of json

        Args:
            line (str): json text string

        Returns:
            Optional[ParsedEvent]: If extracted a parsed event object will be returned
        """
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        timestamp = self._normalize_realtime_timestamp(
            data.get("__REALTIME_TIMESTAMP")
        )

        host = data.get("_HOSTNAME")
        message = data.get("MESSAGE", "")
        pid = self._safe_str(data.get("_PID"))
        severity = self._map_priority(data.get("PRIORITY"))

        program = (
            data.get("SYSLOG_IDENTIFIER")
            or data.get("_SYSTEMD_UNIT")
            or data.get("_COMM")
            or data.get("_EXE")
        )

        fields = {"source_format": "journal_json", "raw_fields": data}

        return ParsedEvent(
            timestamp=timestamp,
            host=host,
            source=None,
            parser_type=self.parser_type,
            program=program,
            pid=pid,
            message=message,
            severity=severity,
            facility=None,
            event_id=None,
            fields=fields,
        )

    def _parse_default_line(self, line: str) -> Optional[ParsedEvent]:
        """Private method for extracting default journal log entries

        Args:
            line (str): string line from the json file

        Returns:
            Optional[ParsedEvent]: If extracted a parsed event object will be returned
        """
        match = JOURNAL_DEFAULT_RE.match(line)
        if not match:
            return None

        data = match.groupdict()

        fields = {
            "source_format": "journal_default",
            "raw_line": line,
        }

        return ParsedEvent(
            timestamp=data.get("timestamp"),
            host=data.get("host"),
            source=None,
            parser_type=self.parser_type,
            program=data.get("tag"),
            pid=data.get("pid"),
            message=data.get("message", ""),
            severity=None,
            facility=None,
            event_id=None,
            fields=fields,
        )

    def _parse_short_iso_line(self, line: str) -> Optional[ParsedEvent]:
        """Private method for extracting the journal entry if the user exported ISO 8601 timestamps

        Args:
            line (str): string line of json containing ISO 8601 timestamps

        Returns:
            Optional[ParsedEvent]: If extracted a parsed event object will be returned
        """
        match = JOURNAL_SHORT_ISO_RE.match(line)
        if not match:
            return None

        data = match.groupdict()

        fields = {
            "source_format": "journal_short_iso",
            "raw_line": line,
        }

        return ParsedEvent(
            timestamp=data.get("timestamp"),
            host=data.get("host"),
            source=None,
            parser_type=self.parser_type,
            program=data.get("tag"),
            pid=data.get("pid"),
            message=data.get("message", ""),
            severity=None,
            facility=None,
            event_id=None,  
            fields=fields,
        )

    def _normalize_realtime_timestamp(self, value: Optional[str]) -> Optional[str]:
        """Convert journal __REALTIME_TIMESTAMP microseconds since epoch to ISO 8601 UTC.
        
        Args:
            value (Optional[str]): extracted timestamp from the journal entry

        Returns:
            Optional[str]: ISO 8601 timestamp from the journal log entry timestamp
        """
        if value is None:
            return None

        try:
            dt = datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, TypeError, OSError):
            return None

    def _map_priority(self, value: Optional[str]) -> Optional[str]:
        """Map journald PRIORITY values to text severity.
        
        Args:
            value (Optional[str]): severity numerical value extracted from the log entry

        Returns:
            Optional[str]: String matching the severity number value
        """
        if value is None:
            return None

        mapping = {
            "0": "emergency",
            "1": "alert",
            "2": "critical",
            "3": "error",
            "4": "warning",
            "5": "notice",
            "6": "info",
            "7": "debug",
        }
        return mapping.get(str(value))

    def _safe_str(self, value: object) -> Optional[str]:
        """Private method to quickly identifying if the value is None

        Args:
            value (object): object value to check

        Returns:
            Optional[str]: String representation of the object
        """
        if value is None:
            return None
        return str(value)