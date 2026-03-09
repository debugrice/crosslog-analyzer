"""
File: crosslog/normalizer/normalize.py
Author: Danny Ray
Date: 03/07/2026
Description: Primary normalizing function file.
"""
from models.event import Event
from models.parsed_event import ParsedEvent
from normalizer.time import normalize_timestamp
from normalizer.helpers import *
from normalizer.auth import enrich_auth_fields

def normalize_event(parsed_event: ParsedEvent) -> Event:
    """Function used by the cross log pipeline to normalize parsed events.

    Args:
        parsed_event (ParsedEvent): Message provided by the designated parser.

    Returns:
        Event: Normalized event to be used by the detect stage.
    """
    normalized_fields = dict(parsed_event.fields or {})
    normalized_fields = enrich_auth_fields(parsed_event, normalized_fields)
    
    # Determine the category of events
    category = determine_category(parsed_event)
    # Determine the event type
    event_type= determine_event_type(parsed_event)
    
    return Event(
        timestamp=normalize_timestamp(
            raw_timestamp=parsed_event.timestamp,
            parser_type=parsed_event.parser_type,
        ),
        host=normalize_host(parsed_event.host),
        source=parsed_event.source,
        parser_type=parsed_event.parser_type,
        program=normalize_program(parsed_event.program, parsed_event.parser_type),
        pid=parsed_event.pid,
        message=normalize_message(parsed_event.message),
        severity=parsed_event.severity,
        facility=parsed_event.facility,
        event_id=parsed_event.event_id,
        category=category,
        event_type=event_type,
        fields=normalized_fields,
    )
    
def determine_category(parsed_event) -> str | None:
    """Function use to determine the category for this parsed event.

    Args:
        parsed_event (ParsedEvent): Message provided by the parser. 

    Returns:
        str | None: string defining the category for this message.
    """
    if parsed_event.parser_type in {"rfc3164", "rfc5424"}:
        if parsed_event.program:
            # TODO More categories will need to be added.
            prog = parsed_event.program.lower()
            if prog in {"sshd", "sudo", "su"}:
                return "authentication"
            if prog in {"kernel", "firewalld", "iptables"}:
                return "network"

    if parsed_event.parser_type in {"evtx", "windows_xml"}:
        # TODO More categories will need to be added.
        if parsed_event.event_id in {4624, 4625, 4634, 4648, 4672, 4740, 4771}:
            return "authentication"
        if parsed_event.event_id in {5156, 5157}:
            return "network"
        if parsed_event.event_id in {6005, 6006, 6008, 1074, 41}:
            return "system"

    return "unknown"


def determine_event_type(parsed_event) -> str | None:
    """Function used to determine the event types for the message.

    Args:
        parsed_event (ParsedEvent): Message provided by the parser.

    Returns:
        str | None: String for the identification number.
    """
    # TODO More event ids will need to be added.
    if parsed_event.parser_type in {"evtx", "windows_xml"}:
        mapping = {
            4624: "logon_success",
            4625: "logon_failure",
            4634: "logoff",
            4672: "special_privileges_assigned",
            4740: "account_lockout",
            4771: "kerberos_pre_authentication_failed",
            5156: "fw_connection_allowed",
            5157: "fw_connection_blocked",
            6005: "eventlog_started",
            6006: "eventlog_stopped",
            6008: "unexpected_shutdown",
            1074: "planned_shutdown",
            41: "kernel_power",
        }
        return mapping.get(parsed_event.event_id, "windows_event")
    # TODO More event ids will need to be added.
    if parsed_event.program:
        prog = parsed_event.program.lower()
        if prog == "sshd":
            return "ssh_event"
        if prog == "sudo":
            return "sudo_event"
        if prog == "su":
            return "su_event"
        if prog == "kernel":
            return "kernel_event"

    return "generic_event"