"""
File: crosslog/models/event.py
Author: Danny Ray
Date: 03/07/2026
Description: Data class used to store the normalized event message.
"""
from dataclasses import dataclass, field
from typing import Any

@dataclass
class Event:
    """
    Data class for the Normalized Event message.
    """
    timestamp: str | None
    host: str | None
    source: str
    parser_type: str
    program: str | None
    pid: int | None
    message: str
    severity: int | None = None
    facility: int | None = None
    event_id: int | None = None
    category: str | None = None
    event_type: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)