import re

from models.event import Event
from models.finding import Finding

# Extract the unit/service name from systemd messages like:
#   "Started OpenSSH server daemon."
#   "Stopped The Apache HTTP Server."
#   "Failed to start MySQL Database Server."
_UNIT_RE = re.compile(
    r"(?:Started|Stopped|Failed to start)\s+(.+?)(?:\.|$)", re.IGNORECASE
)


def _extract_unit(message: str) -> str | None:
    m = _UNIT_RE.search(message or "")
    return m.group(1).strip() if m else None


def detect_systemd_service_started(event: Event) -> Finding | None:
    """Detect a systemd service or unit entering the started state.

    Matches journal/syslog events where program=systemd and the message
    begins with "Started".

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if a service start is detected, else None.
    """
    if event.program != "systemd":
        return None
    if not (event.message or "").lower().startswith("started"):
        return None

    unit = _extract_unit(event.message)
    title = f"Linux service started: {unit}" if unit else "Linux service started"

    return Finding(
        rule_id="LINUX-SERVICE-STARTED",
        title=title,
        severity="info",
        category="service_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0003",
        mitre_tactic_name="Persistence",
    )


def detect_systemd_service_stopped(event: Event) -> Finding | None:
    """Detect a systemd service or unit entering the stopped state.

    Matches journal/syslog events where program=systemd and the message
    begins with "Stopped".

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if a service stop is detected, else None.
    """
    if event.program != "systemd":
        return None
    if not (event.message or "").lower().startswith("stopped"):
        return None

    unit = _extract_unit(event.message)
    title = f"Linux service stopped: {unit}" if unit else "Linux service stopped"

    return Finding(
        rule_id="LINUX-SERVICE-STOPPED",
        title=title,
        severity="info",
        category="service_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0003",
        mitre_tactic_name="Persistence",
    )


def detect_systemd_service_failed(event: Event) -> Finding | None:
    """Detect a systemd service or unit that has failed.

    Matches journal/syslog events where program=systemd and the message
    contains "Failed".

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if a service failure is detected, else None.
    """
    if event.program != "systemd":
        return None
    if "failed" not in (event.message or "").lower():
        return None

    unit = _extract_unit(event.message)
    title = f"Linux service failed: {unit}" if unit else "Linux service failed"

    return Finding(
        rule_id="LINUX-SERVICE-FAILED",
        title=title,
        severity="high",
        category="service_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0003",
        mitre_tactic_name="Persistence",
    )


RULES = [
    detect_systemd_service_started,
    detect_systemd_service_stopped,
    detect_systemd_service_failed,
]
