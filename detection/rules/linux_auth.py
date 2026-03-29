
from models.finding import Finding

def detect_ssh_failed_password(event):
    """Function used to detect ssh failed password attempts.

    Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding object extracted from the normalized event message.
    """
    # Program check if its from the ssh daemon
    if event.program != "sshd":
        return None

    # String lower case the message
    msg = event.message.lower()

    # Message must have the phrase failed password.
    if "failed password" not in msg:
        return None

    return Finding(
        rule_id="LINUX-SSH-FAILED-PASSWORD",
        title="Failed SSH password attempt",
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

def detect_ssh_success(event):
    """Function used to detect ssh successful password logon.

    Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.program != "sshd":
        return None

    # String lower case the message
    msg = event.message.lower()

    # checking for specific phrases in the msg.
    # TODO See if this can be improved.
    if "accepted password" not in msg and "accepted publickey" not in msg:
        return None

    return Finding(
        rule_id="LINUX-SSH-SUCCESS",
        title="Successful SSH login",
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

def detect_sudo_usage(event):
    """Function used to detect sudo usage.

    Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.program != "sudo":
        return None

    return Finding(
        rule_id="LINUX-SUDO-USAGE",
        title="Sudo command executed",
        severity="medium",
        category="privilege",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0004",
        mitre_tactic_name="Privilege Escalation",
    )

def detect_pam_faillock_lockout(event):
    """Function used to detect account lockout.

    Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    #TODO Need to add other types of logons; other than ssh
    if event.program != "sshd":
        return None

    # Must have the phrase pam_faillock
    if "pam_faillock" not in event.message:
        return None

    # Needs to have the extract event fields calling out lockout.
    if not event.fields.get("lockout"):
        return None

    return Finding(
        rule_id="LINUX-PAM-FAILLOCK-LOCKOUT",
        title="Linux account temporarily locked after failed logins",
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

# List of failure patterns for kerberos.
KRB5_FAILURE_PATTERNS = (
    "client_not_found",
    "preauth_failed",
    "client not found in kerberos database",
    "password incorrect",
    "authentication failed",
    "krb5_auth_fail",
    "client_revoked",
)

# List of program names associated with kerberos.
KRB5_PROGRAMS = {
    "krb5kdc",
    "kadmind",
    "sssd",
}

def detect_kerberos_login_failure(event):
    """Function used to detect kerberos failed logins.

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    program = (event.program or "").lower()
    message = (event.message or "").lower()

    # Narrow to likely Kerberos producers first
    if program not in KRB5_PROGRAMS and "krbtgt" not in message:
        return None

    matched_reason = None
    # Check if the pattern is in the provided message.
    for pattern in KRB5_FAILURE_PATTERNS:
        if pattern in message:
            matched_reason = pattern
            break

    # No pattern match for a reason; then it will fail.
    if matched_reason is None:
        return None

    return Finding(
        rule_id="KRB5-LOGIN-FAILURE",
        title="Kerberos login failure",
        severity="medium",
        category="authentication",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type="kerberos_login_failure",
        message=event.message,
        fields={
            **dict(event.fields),
            "auth_protocol": "kerberos",
            "failure_reason": matched_reason,
        },
        mitre_tactic_id="TA0006",
        mitre_tactic_name="Credential Access",
    )

# List of rules used for linux authentication detection
RULES = [
    detect_ssh_failed_password,
    detect_ssh_success,
    detect_sudo_usage,
    detect_pam_faillock_lockout,
    detect_kerberos_login_failure,
]
