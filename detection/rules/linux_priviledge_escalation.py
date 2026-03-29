
from models.event import Event
from models.finding import Finding

# List of privilege events to track
PRIV_SYSCALLS = { "59" } # EXECVE

def detect_privilege_escalation(event: Event) -> Finding | None:
    """Function used to detect whether a set of audit events contain privilege escalation.

    Args:
        event (Event): Normalized event

    Returns:
        Finding | None: Returns a finding object is detected; None is not detected
    """
    # Only audit parsed messages will be used to detect privilege escalation
    if event.parser_type != "auditd":
        return None

    # TODO Only checks if the EXECVE
    if str(event.fields.get("syscall")) not in  PRIV_SYSCALLS:
        return None

    # Extract the user id and the effective user id
    uid = event.fields.get("uid")
    euid = event.fields.get("euid")

    # Without the user id and effective user id we need to stop
    if uid is None or euid is None:
        return None

    # If the ids are the same, then there is no escalation
    if uid == euid:
        return None

    command_line = event.fields.get("command_line")
    program = event.program or event.fields.get("comm")

    return Finding(
        rule_id="PRIVILEGE_ESCALATION",
        title="Privilege Escalation Detected",
        severity="high",
        category="privilege",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type="privilege_escalation",
        message=f"User {uid} escalated privileges to {euid}: {command_line or program}",
        fields=dict(event.fields),
        mitre_tactic_id="TA0004",
        mitre_tactic_name="Privilege Escalation",
    )

RULES = [
    detect_privilege_escalation,
]
