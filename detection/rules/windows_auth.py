
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
    )

# List of rules used to detect Windows authentication events
RULES = [
    detect_windows_logon_success,
    detect_windows_logon_failure,
    detect_windows_kerberos_pre_auth_failure,
    detect_windows_account_lockout,
    detect_windows_priviledge_logon,
]