from dataclasses import dataclass, field
from models.parsed_event import ParsedEvent

@dataclass
class AuditdMergedEvent:
    """
    Class used to store the collection of parsed events to form a single event
    """
    audit_id: str
    records: list[ParsedEvent] = field(default_factory=list)

    