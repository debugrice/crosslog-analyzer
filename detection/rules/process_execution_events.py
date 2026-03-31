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

# Syscalls related to process creation
PROCESS_CREATE_SYSCALLS = {"59", "322"}  # execve, execveat

# Syscalls related to process termination
PROCESS_TERMINATE_SYSCALLS = {"60", "231"}  # exit, exit_group

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
        mitre_tactic_id="TA0006",
        mitre_tactic_name="Credential Access",
    )

def detect_process_creation(event: Event) -> Finding | None:
    """Detect process creation from Linux auditd syscall records.

    Args:
        event (Event): Normalized Event message

    Returns:
        Finding | None: Returns a Finding if a process creation event is detected.
    """
    # Must be from auditd
    if event.parser_type != "auditd":
        return None

    # Must be the syscall anchor record
    if event.fields.get("record_type") != "SYSCALL":
        return None

    syscall = str(event.fields.get("syscall", ""))
    if syscall not in PROCESS_CREATE_SYSCALLS:
        return None

    program = event.program or event.fields.get("comm") or "unknown"
    command_line = event.fields.get("command_line")
    exe = event.fields.get("exe")
    pid = event.fields.get("pid")
    ppid = event.fields.get("ppid")
    uid = event.fields.get("uid")
    euid = event.fields.get("euid")
    success = event.fields.get("success")

    display_cmd = command_line or exe or program

    if success == "yes":
        severity = "low"
        event_type = "process_create"
        message = f'Process created: {display_cmd}'
    else:
        severity = "medium"
        event_type = "process_create_attempt"
        message = f'Process creation attempt failed: {display_cmd}'

    return Finding(
        rule_id="LINUX_PROCESS_CREATE",
        title="Process creation detected",
        severity=severity,
        category="process",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event_type,
        message=message,
        fields={
            **dict(event.fields),
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "euid": euid,
            "exe": exe,
            "program": program,
            "command_line": command_line,
        },
        mitre_tactic_id="TA0002",
        mitre_tactic_name="Execution",
    )


def detect_process_termination(event: Event) -> Finding | None:
    """Detect process termination from Linux auditd syscall records.

    Args:
        event (Event): Normalized Event message

    Returns:
        Finding | None: Returns a Finding if a process termination event is detected.
    """
    # Must be from auditd
    if event.parser_type != "auditd":
        return None

    # Must be the syscall anchor record
    if event.fields.get("record_type") != "SYSCALL":
        return None

    syscall = str(event.fields.get("syscall", ""))
    if syscall not in PROCESS_TERMINATE_SYSCALLS:
        return None

    program = event.program or event.fields.get("comm") or "unknown"
    exe = event.fields.get("exe")
    pid = event.fields.get("pid")
    ppid = event.fields.get("ppid")
    uid = event.fields.get("uid")
    euid = event.fields.get("euid")
    exit_code = event.fields.get("exit")

    display_name = exe or program

    if exit_code == "0":
        severity = "low"
        event_type = "process_terminated"
        message = f'Process terminated normally: {display_name}'
    else:
        severity = "medium"
        event_type = "process_terminated_abnormal"
        message = f'Process terminated abnormally: {display_name} (exit={exit_code})'

    return Finding(
        rule_id="LINUX_PROCESS_TERMINATE",
        title="Process termination detected",
        severity=severity,
        category="process",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event_type,
        message=message,
        fields={
            **dict(event.fields),
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "euid": euid,
            "exe": exe,
            "program": program,
            "exit_code": exit_code,
        },
        mitre_tactic_id="TA0005",
        mitre_tactic_name="Defense Evasion",
    )

RULES = [
    detect_sensitive_file_access,
    detect_process_creation,
    detect_process_termination,
]
