from models.finding import Finding

def detect_windows_user_account_creation(event):
    """Function used to detect a Windows user account was created. 

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4720:
        return None

    return Finding(
        rule_id="WIN-4720-USER-CREATED",
        title="Windows User Created",
        severity="info",
        category="user_account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
    )
    
def detect_windows_user_account_deleted(event):
    """Function used to detect a Windows user account was deleted. 

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4726:
        return None

    return Finding(
        rule_id="WIN-4726-USER-DELETED",
        title="Windows User Deleted",
        severity="info",
        category="user_account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
    )

def detect_windows_user_password_change(event):
    """Function used to detect a Windows user password change attempt. 

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4723:
        return None

    return Finding(
        rule_id="WIN-4726-USER-PASSWORD-CHANGE",
        title="Windows User Password Change",
        severity="info",
        category="user_account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
    )
    
def detect_windows_user_group_membership_change(event):
    """Function used to detect a Windows user group membership change. 

     Args:
        event (ParsedEvent): Normalized event message.

    Returns:
        Finding: Finding extracted from the normalized event message.
    """
    if event.event_id != 4732:
        return None

    return Finding(
        rule_id="WIN-4726-USER-GROUP-MEMBERSHIP-CHANGE",
        title="Windows User Group Membership Change",
        severity="info",
        category="user_account_management",
        source=event.source,
        timestamp=event.timestamp,
        host=event.host,
        event_type=event.event_type,
        message=event.message,
        fields=dict(event.fields),
    )

RULES = [
    detect_windows_user_account_creation,
    detect_windows_user_account_deleted,
    detect_windows_user_password_change,
    detect_windows_user_group_membership_change,
]