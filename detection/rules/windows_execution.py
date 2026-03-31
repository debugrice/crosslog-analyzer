from models.finding import Finding

def detect_windows_process_created(event):
    """Function used to detect a windows process created.

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4688:
        return None

    return Finding(
        rule_id="WIN-4688-PROCESS-CREATed",
        title="Windows Process Created",
        severity="low",
        category="execution",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0002",
        mitre_tactic_name="Execution",
    )
def detect_windows_process_terminated(event):
    """Function used to detect a windows process terminated.

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4689:
        return None

    return Finding(
        rule_id="WIN-4689-PROCESS-TERMINATED",
        title="Windows Process Terminated",
        severity="low",
        category="execution",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0002",
        mitre_tactic_name="Execution",
    )
RULES = [
    detect_windows_process_created,
    detect_windows_process_terminated,
]