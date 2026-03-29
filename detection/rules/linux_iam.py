import re

from models.event import Event
from models.finding import Finding

# Matches acct="username" inside auditd msg body
_ACCT_RE = re.compile(r'acct="([^"]+)"')

# auditd record types that signal group-level changes
_GROUP_RECORD_TYPES = {"ADD_GROUP", "DEL_GROUP"}

# syslog programs that indicate group/account changes other than useradd/userdel/passwd
_GROUP_SYSLOG_PROGRAMS = {"usermod", "groupadd", "groupdel"}


def _extract_acct(message: str) -> str | None:
    """Extract the account name from an auditd inner msg string.

    auditd encodes the target account as acct="username" inside the msg=
    body, e.g. op=adding user acct="devops" exe="..." res=success.

    Args:
        message (str): event.message produced from the auditd msg= value.

    Returns:
        str | None: account name if found, else None.
    """
    m = _ACCT_RE.search(message or "")
    return m.group(1) if m else None


def _title(base: str, acct: str | None) -> str:
    """Append account name to a finding title when available."""
    return f"{base}: {acct}" if acct else base


def detect_linux_user_created(event: Event) -> Finding | None:
    """Detect Linux user account creation.

    Covers two sources:
    - syslog (rfc3164 / journal): program=useradd, message contains "new user:"
    - auditd: record_type=ADD_USER

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if user creation is detected, else None.
    """
    acct = None

    if event.program == "useradd":
        if "new user:" not in (event.message or "").lower():
            return None
        # syslog useradd format: "new user: name=foo, UID=1001, ..."
        m = re.search(r"name=([^,\s]+)", event.message or "")
        acct = m.group(1).strip() if m else None

    elif event.parser_type == "auditd" and event.fields.get("record_type") == "ADD_USER":
        acct = _extract_acct(event.message)

    else:
        return None

    return Finding(
        rule_id="LINUX-IAM-USER-CREATED",
        title=_title("Linux user account created", acct),
        severity="info",
        category="user_account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0003",
        mitre_tactic_name="Persistence",
    )


def detect_linux_user_deleted(event: Event) -> Finding | None:
    """Detect Linux user account deletion.

    Covers two sources:
    - syslog: program=userdel, message contains "delete user"
    - auditd: record_type=DEL_USER

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if user deletion is detected, else None.
    """
    acct = None

    if event.program == "userdel":
        if "delete user" not in (event.message or "").lower():
            return None
        # syslog userdel format: "delete user 'foo'" or "delete user foo"
        m = re.search(r"delete user ['\"]?([^'\"]+)['\"]?", event.message or "", re.IGNORECASE)
        acct = m.group(1).strip() if m else None

    elif event.parser_type == "auditd" and event.fields.get("record_type") == "DEL_USER":
        acct = _extract_acct(event.message)

    else:
        return None

    return Finding(
        rule_id="LINUX-IAM-USER-DELETED",
        title=_title("Linux user account deleted", acct),
        severity="medium",
        category="user_account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0040",
        mitre_tactic_name="Impact",
    )


def detect_linux_password_changed(event: Event) -> Finding | None:
    """Detect Linux password change.

    Covers two sources:
    - syslog: program=passwd AND message contains "password changed for"
      (logged via PAM as: pam_unix(passwd:chauthtok): password changed for alice)
    - auditd: record_type=USER_CHAUTHTOK

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if password change is detected, else None.
    """
    acct = None

    if event.program == "passwd":
        msg = (event.message or "").lower()
        if "password changed for" not in msg:
            return None
        # PAM format: "...password changed for alice"
        m = re.search(r"password changed for (\S+)", event.message or "", re.IGNORECASE)
        acct = m.group(1).strip() if m else None

    elif event.parser_type == "auditd" and event.fields.get("record_type") == "USER_CHAUTHTOK":
        acct = _extract_acct(event.message)

    else:
        return None

    return Finding(
        rule_id="LINUX-IAM-PASSWORD-CHANGED",
        title=_title("Linux user password changed", acct),
        severity="info",
        category="user_account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
        mitre_tactic_id="TA0003",
        mitre_tactic_name="Persistence",
    )


def detect_linux_group_membership_change(event: Event) -> Finding | None:
    """Detect Linux group creation, deletion, or membership change.

    Covers two sources:
    - syslog: program in {usermod, groupadd, groupdel}
    - auditd: record_type in {ADD_GROUP, DEL_GROUP}

    Args:
        event (Event): Normalized event.

    Returns:
        Finding | None: Finding if a group change is detected, else None.
    """
    acct = None

    if event.program in _GROUP_SYSLOG_PROGRAMS:
        # usermod: "add 'alice' to group 'docker'"
        # groupadd: "new group: name=devteam, GID=1002"
        # groupdel: "delete group 'devteam'" or "delete group devteam"
        msg = event.message or ""
        grp_m = re.search(r"group ['\"]?([^'\"]+)['\"]?", msg, re.IGNORECASE)
        acct = grp_m.group(1).strip() if grp_m else None

    elif event.parser_type == "auditd" and event.fields.get("record_type") in _GROUP_RECORD_TYPES:
        acct = _extract_acct(event.message)

    else:
        return None

    return Finding(
        rule_id="LINUX-IAM-GROUP-CHANGE",
        title=_title("Linux group membership change", acct),
        severity="info",
        category="user_account_management",
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
    detect_linux_user_created,
    detect_linux_user_deleted,
    detect_linux_password_changed,
    detect_linux_group_membership_change,
]
