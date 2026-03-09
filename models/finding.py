"""
File: crosslog/models/finding.py
Author: Danny Ray
Date: 03/07/2026
Description: Data class for storing the findings from the detection stage.
"""
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