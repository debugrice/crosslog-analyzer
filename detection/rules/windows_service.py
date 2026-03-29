from models.finding import Finding


def detect_windows_service_installed(event) -> Finding | None:
    """Detect a Windows service installation via Security log event 4697.

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if a service was installed, else None.
    """
    if event.event_id != 4697:
        return None

    service_name = event.fields.get("ServiceName")
    title = f"Windows service installed: {service_name}" if service_name else "Windows service installed"

    return Finding(
        rule_id="WIN-4697-SERVICE-INSTALLED",
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


def detect_windows_service_state_change(event) -> Finding | None:
    """Detect a Windows service state change via System log event 7036.

    EventData fields: param1 = service name, param2 = new state.

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if a service state change is detected, else None.
    """
    if event.event_id != 7036:
        return None

    service_name = event.fields.get("param1")
    state = event.fields.get("param2")
    parts = [p for p in [service_name, state] if p]
    title = "Windows service state change: " + " → ".join(parts) if parts else "Windows service state change"

    return Finding(
        rule_id="WIN-7036-SERVICE-STATE-CHANGE",
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


def detect_windows_new_service_installed(event) -> Finding | None:
    """Detect a new Windows service registration via System log event 7046.

    EventData fields: param1 = service type, param2 = service name.

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if a new service is registered, else None.
    """
    if event.event_id != 7046:
        return None

    service_name = event.fields.get("param2")
    title = f"Windows new service registered: {service_name}" if service_name else "Windows new service registered"

    return Finding(
        rule_id="WIN-7046-NEW-SERVICE-REGISTERED",
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
    detect_windows_service_installed,
    detect_windows_service_state_change,
    detect_windows_new_service_installed,
]
