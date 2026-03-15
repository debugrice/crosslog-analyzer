
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