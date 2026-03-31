
from models.finding import Finding

def detect_windows_logon_success(event):
    """Function used to detect a successful Windows logon.

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4624:
        return None

    return Finding(
        rule_id="WIN-4624-LOGON-SUCCESS",
        title="Windows logon success",
        severity="low",
        category="authentication",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0001",
        mitre_tactic_name="Initial Access",
    )

def detect_windows_logon_failure(event):
    """Function used to detect a failed Windows logon.

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4625:
        return None

    return Finding(
        rule_id="WIN-4625-LOGON-FAILURE",
        title="Windows logon failure",
        severity="medium",
        category="authentication",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0006",
        mitre_tactic_name="Credential Access",
    )

def detect_windows_kerberos_pre_auth_failure(event):
    """Function used to detect a failed Windows Kerberos logon

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4771:
        return None
    return Finding(
        rule_id="WIN-4771-KERBEROS-PRE-AUTH-FAILURE",
        title="Windows Kerberos login failure",
        severity="medium",
        category="authentication",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0006",
        mitre_tactic_name="Credential Access",
    )

def detect_windows_account_lockout(event):
    """Function to detect a Windows account lockout.

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4740:
        return None
    return Finding(
        rule_id="WIN-4740-ACCOUNT-LOCKOUT",
        title="Windows Account Lockout",
        severity="high",
        category="authentication",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0006",
        mitre_tactic_name="Credential Access",
    )

def detect_windows_priviledge_logon(event):
    """Function to detect a Windows special priviledge logon.

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4672:
        return None
    return Finding(
        rule_id="WIN-4672-PRIVILEGED-LOGON",
        title="Windows Privileged Logon",
        severity="medium",
        category="authentication",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0004",
        mitre_tactic_name="Privilege Escalation",
    )

def detect_dsrm_password_set(event) -> Finding | None:
    """Detect attempts to set Directory Services Restore Mode (DSRM) password (Event ID 4794)."""

    # Must be Windows event log
    if event.parser_type not in {"evtx", "windows_xml"}:
        return None

    # Must match Event ID 4794
    if str(event.event_id) != "4794":
        return None

    subject_user = event.fields.get("SubjectUserName")
    subject_domain = event.fields.get("SubjectDomainName")
    logon_id = event.fields.get("SubjectLogonId")

    user_display = f"{subject_domain}\\{subject_user}" if subject_domain and subject_user else subject_user or "unknown"

    severity = "high"
    event_type = "dsrm_password_set"

    message = f'DSRM password set/reset attempt by {user_display}'

    return Finding(
        rule_id="WIN-4794-DSRM-PASSWORD-SET",
        title="DSRM password modification detected",
        severity=severity,
        category="account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event_type,
        message=message,
        fields={
            **dict(event.fields),
            "subject_user": subject_user,
            "subject_domain": subject_domain,
            "logon_id": logon_id,
        },
        mitre_tactic_id="TA0003",
        mitre_tactic_name="Persistence",
    )

# List of rules used to detect Windows authentication events
RULES = [
    detect_windows_logon_success,
    detect_windows_logon_failure,
    detect_windows_kerberos_pre_auth_failure,
    detect_windows_account_lockout,
    detect_windows_priviledge_logon,
    detect_dsrm_password_set,
]
