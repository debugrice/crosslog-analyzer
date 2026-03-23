import re

from models.parsed_event import ParsedEvent
from parsers.baseline_parser import BaseLineParser


AUDIT_LINE_RE = re.compile(
    r"^type=(?P<record_type>\w+)\s+"
    r"msg=audit\((?P<timestamp>\d+(?:\.\d+)?):(?P<event_id>\d+)\):\s*"
    r"(?P<body>.*)$"
)

AUDIT_KEYVAL_RE = re.compile(
    r'(?P<key>\w+)=(".*?"|\'.*?\'|\S+)'
)

class AuditParser(BaseLineParser):
    """Linux audit.log parser implementation.

    Args:
        BaseLineParser (_type_): Parent base logger class.
    """

    parser_type = "auditd"

    def parse_line( self, line: str, source: str, line_number: int | None = None) -> ParsedEvent:
        """Overridden method to extract and parse each auditd line.

        Args:
            line (str): Line of data from the text file.
            source (str): File providing the data.
            line_number (int | None, optional): Line number. Defaults to None.

        Raises:
            ValueError: If the parser fails, it will throw an exception.

        Returns:
            ParsedEvent: Parsed object from the provided string.
        """
        ret_line = AUDIT_LINE_RE.match(line)

        if not ret_line:
            raise ValueError("Line is not valid auditd format")
        
        # Matching regex extracted fields
        record_type = ret_line.group("record_type")
        timestamp = ret_line.group("timestamp")
        audit_id = int(ret_line.group("event_id"))
        body = ret_line.group("body")

        fields = {
            "line_number": line_number,
            "record_type": record_type,
            "event_id": audit_id,
        }

        # Extract additional key-value pairs
        for match in AUDIT_KEYVAL_RE.finditer(body):
            key = match.group("key")
            value = match.group(0).split("=", 1)[1]
            fields[key] = self._strip_quotes(value)

        pid = self._safe_int(fields.get("pid"))

        message = self._build_message(record_type, fields, body)

        return ParsedEvent(
            source=source,
            parser_type=self.parser_type,
            timestamp=timestamp,
            program="auditd",
            host=None,
            pid=pid,
            message=message,
            severity=None,
            facility=None,
            fields=fields,
        )

    @staticmethod
    def _strip_quotes(value: str) -> str:
        """Remove wrapping single or double quotes."""
        if len(value) >= 2 and (
            (value[0] == '"' and value[-1] == '"')
            or (value[0] == "'" and value[-1] == "'")
        ):
            return value[1:-1]
        return value

    @staticmethod
    def _safe_int(value: str | None) -> int | None:
        """Safely convert a string to int."""
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _build_message(record_type: str, fields: dict, fallback: str) -> str:
        """Build a readable message from the audit record."""
        if record_type == "EXECVE":
            argc = AuditParser._safe_int(fields.get("argc"))
            if argc:
                args = []
                for i in range(argc):
                    arg = fields.get(f"a{i}")
                    if arg is not None:
                        args.append(arg)
                if args:
                    return " ".join(args)

        if "msg" in fields:
            return str(fields["msg"])

        if "exe" in fields:
            return f'{record_type} exe={fields["exe"]}'

        return fallback