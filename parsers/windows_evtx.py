
from pathlib import Path
from evtx import PyEvtxParser
from models.parsed_event import ParsedEvent, ParserErrorEvent

class EvtxParser:
    """Implementation of the Windows EVTX file parser

    Yields:
        ParsedEvent|ParsedErrorEvent: Yields messages extracted from the file. 
    """
    parser_type = "evtx"
    
    def parse_file(self, file_path: Path):
        try:
            # Implementation of the evtx import
            parser = PyEvtxParser(str(file_path))
            
            # For loop to process all the records in the file.
            for record in parser.records():
                try:
                    # Private formatting method
                    event = self._convert_record(file_path, record)
                    yield event
                except Exception as exc:
                    yield ParserErrorEvent(
                        source=str(file_path),
                        parser_type=self.parser_type,
                        raw_record=str(record),
                        error=str(exc),
                    )
        except Exception as exc:
            yield ParserErrorEvent(
                source=str(file_path),
                parser_type=self.parser_type,
                raw_record="",
                error=f"Failed to open EVTX: {exc}",
            )
    def _convert_record(self, file_path: Path, record: dict) -> ParsedEvent:
        """Formats the record message into the Cross Log parsed format.

        Args:
            file_path (Path): Path object to the file source.
            record (dict): Extract record from the Windows binary log file.

        Returns:
            ParsedEvent: Windows parsed event message.
        """
        return ParsedEvent(
            source=str(file_path),
            parser_type=self.parser_type,
            timestamp=record.get("timestamp"),
            host=record.get("computer"),
            program=record.get("provider"),
            pid=None,
            message=str(record.get("data")),
            event_id=record.get("event_id"),
            fields={
                "channel": record.get("channel"),
                "provider": record.get("provider"),
                "raw": record.get("data"),
            },
        )
        