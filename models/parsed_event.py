"""
File: crosslog/models/parsed_event.py
Author: Danny Ray
Date: 03/07/2026
Description: Data class for storing the parsed event from the log files.
"""
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ParsedEvent:
    """Data class for storing the parsed event messages from the log files.
    """
    source: str
    parser_type: str
    timestamp: str | None
    host: str | None
    program: str | None
    pid: int | None
    message: str
    severity: int | None = None
    facility: int | None = None
    event_id: int | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    
@dataclass
class ParserErrorEvent:
    """Data class for storing errors from the parser if something stops parsing.
    """
    source: str
    parser_type: str
    raw_record: str
    error: str
    line_number: int | None = None
