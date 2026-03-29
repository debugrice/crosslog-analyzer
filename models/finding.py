
from dataclasses import dataclass, field
from typing import Any

@dataclass
class Finding:
    """Data class for the finding message.
    """
    rule_id: str
    title: str
    severity: str
    category: str
    source: str
    timestamp: str | None
    host: str | None
    event_type: str | None
    message: str
    fields: dict[str, Any] = field(default_factory=dict)
    mitre_tactic_id: str | None = None    # e.g. "TA0006"
    mitre_tactic_name: str | None = None  # e.g. "Credential Access"