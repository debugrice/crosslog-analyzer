
import re

# Regex matching filter for sshd failed login
SSHD_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
)

# Regex matching filter for pam_faillock
PAM_FAILLOCK_RE = re.compile(
    r"pam_faillock\((?P<service>[^:]+):auth\):\s+user\s+(?P<username>\S+)\s+is\s+locked\s+out",
    re.IGNORECASE,
)

def enrich_auth_fields(parsed_event, fields):
    """Helper function used to extract the linux auth fields

    Args:
        parsed_event (ParsedEvent): Parsed event message from the linux parser.
        fields (dict): Dictionary of the linux auth fields

    Returns:
        dict: Updated field values
    """

    message = parsed_event.message

    # Check if this is a ssh event
    ssh_match = SSHD_FAILED_RE.search(message)
    if ssh_match:
        fields["username"] = ssh_match.group("username")
        fields["source_ip"] = ssh_match.group("source_ip")
        fields["source_port"] = int(ssh_match.group("port"))
        fields["auth_service"] = "sshd"

    # Check if this is a pam_faillock event
    faillock_match = PAM_FAILLOCK_RE.search(message)
    if faillock_match:
        fields["username"] = faillock_match.group("username")
        fields["auth_service"] = faillock_match.group("service")
        fields["lockout"] = True

    return fields