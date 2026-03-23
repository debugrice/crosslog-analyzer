from models.finding import Finding
from models.event import Event

# List of sensitive files to track
SENSITIVE_FILES = {
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
}

# List of syscalls to use for checking if the file is open
CHK_SYSCALLS = {"2", "257", "59" }  # open, openat, execve

def detect_sensitive_file_access(event: Event) -> Finding | None:
    """Detect access to sensitive files if the syscall matches the check list.

    Args:
        event (Event): Normalized Event message

    Returns:
        Finding | None: If a finding is detected, returns Finding. Else None
    """
    # Must use the audit log to detect
    if event.parser_type != "auditd":
        return None

    # Must be a ssycall
    if event.fields.get("record_type") != "SYSCALL":
        return None
    
    # Extract the actual syscall value from the event
    syscall = event.fields.get("syscall")
    if syscall not in CHK_SYSCALLS:
        return None

    # 
    argv = event.fields.get("argv", [])
    paths = event.fields.get("paths", [])
    command_line = event.fields.get("command_line")
    program = event.program or event.fields.get("comm") or "unknown"

    matched_paths = [p for p in paths if p in SENSITIVE_FILES]
    matched_argv = [a for a in argv if a in SENSITIVE_FILES]
    matched = matched_paths or matched_argv

    display_cmd = command_line or program
    
    if not matched:
        return None

    target = matched[0]
    success = event.fields.get("success")
    uid = event.fields.get("uid")
    euid = event.fields.get("euid")
    
    if success == "yes":
        severity = "high"
        event_type = "sensitive_file_access"
        message = f'{display_cmd} accessed sensitive file "{target}"'
    else:
        severity = "medium"
        event_type = "sensitive_file_access_attempt"
        message = f'{display_cmd} attempted to access sensitive file "{target}"'

    return Finding(
        rule_id="SENSITIVE_FILE_ACCESS",
        title="Unauthorized sensitive file access",
        severity=severity,
        category="file_access",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event_type,
        message=message,
        fields=dict(event.fields),
    )
    
RULES = [
    detect_sensitive_file_access,
]