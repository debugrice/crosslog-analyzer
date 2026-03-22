from models.parsed_event import ParsedEvent
from models.audit_event import AuditdMergedEvent

class AuditdEventAggregator:
    """Class used to process aggregated auditd events. 
    The audit_id can stretch across multiple type messages.
    """
    def __init__(self):
        self.current_audit_id: str | None = None
        self.bucket: list[ParsedEvent] = []

    def process(self, parser_event: ParsedEvent) -> AuditdMergedEvent | None:
        """Method takes a parsed event message and groups them together. 
        Returns the list of merged audit records when the audit_id changes.

        Args:
            parser_event (ParsedEvent): Parsed event message

        Returns:
            AuditdMergedEvent | None: Merged list of records when the id changes. 
            Else it returns None
        """
        # Grab the audit id from them message
        audit_id = parser_event.fields.get("event_id")
        
        # No audit id so we're done
        if not audit_id:
            return None

        # Update the current class audit id with this event audit id and save the event
        if self.current_audit_id is None:
            self.current_audit_id = audit_id
            self.bucket.append(parser_event)
            return None

        # Event has not changed, so store it and exit
        if audit_id == self.current_audit_id:
            self.bucket.append(parser_event)
            return None

        # Audit id has changed create the merged list of events
        merged = AuditdMergedEvent(
            audit_id=self.current_audit_id,
            records=self.bucket,
        )

        # Save the new audit id and drop the old list of records and save this new one
        self.current_audit_id = audit_id
        self.bucket = [parser_event]
        return merged

    def flush(self) -> AuditdMergedEvent | None:
        """Method provides a way to close out the last audit event in the file.

        Returns:
            AuditdMergedEvent | None:  Merged list of records
        """
        # Check the attributes are empty its done
        if not self.bucket or not self.current_audit_id:
            return None

        # Create the last merged event
        grouped_event = AuditdMergedEvent(
            audit_id=self.current_audit_id,
            records=self.bucket.copy(),
        )

        # Clean up the attributes
        self.current_audit_id = None
        self.bucket = []
        
        return grouped_event
