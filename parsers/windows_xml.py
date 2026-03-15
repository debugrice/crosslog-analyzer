
from pathlib import Path
import xml.etree.ElementTree as ET

from models.parsed_event import ParsedEvent, ParserErrorEvent

class WindowsXmlParser:
    """Implementation of the Windows XML parser class.

    Returns:
        None: If the class fails to parse, then it will exit.

    Yields:
        ParsedEvent | ParsedErrorEvent: Messages extracted during parsing.
    """
    parser_type = "windows_xml"
    
    def parse_file(self, file_path: Path):
        try:
            # Basic XML parsing
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as exc:
            yield ParserErrorEvent(
                source=str(file_path),
                parser_type=self.parser_type,
                raw_record="",
                error=f"Failed to parse XML: {exc}",
            )
            return
        
        # Plan for multiple events to be in the XML
        event_elements = []
        
        # Check to see how many events are present in the file.
        if self._strip_ns(root.tag) == "Event":
            event_elements = [root]
        else:
            event_elements = [elem for elem in root if self._strip_ns(elem.tag) == "Event"]

        # Loop through all the events and process the records.
        for index, event_elem in enumerate(event_elements, start=1):
            try:
                # Triggers the update of the parsed message.
                yield self._parse_event_element(file_path, event_elem, index)
            except Exception as exc:
                yield ParserErrorEvent(
                    source=str(file_path),
                    parser_type=self.parser_type,
                    raw_record=ET.tostring(event_elem, encoding="unicode"),
                    error=str(exc),
                    line_number=index,
                )
    
    def _parse_event_element(self, file_path: Path, event_elem, record_number: int) -> ParsedEvent:
        """Extracts the record data to the correct format for cross log parser.

        Args:
            file_path (Path): Path to the source file.
            event_elem (Element): XML event tag data.
            record_number (int): Number of the current record in the file.

        Returns:
            ParsedEvent: Cross log parsed event message
        """
        # Matching namespace used to filter out unwanted XML files.
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        system = event_elem.find("e:System", ns)
        event_data = event_elem.find("e:EventData", ns)

        timestamp = None
        host = None
        provider = None
        event_id = None
        channel = None
        fields = {}

        # Use the namespace to extract the necessary data from the Windows XML Log file.
        # NOTE this will cause the XML to be ignored.
        if system is not None:
            provider_el = system.find("e:Provider", ns)
            if provider_el is not None:
                provider = provider_el.attrib.get("Name")

            event_id_el = system.find("e:EventID", ns)
            if event_id_el is not None and event_id_el.text:
                try:
                    event_id = int(event_id_el.text)
                except ValueError:
                    event_id = None

            computer_el = system.find("e:Computer", ns)
            if computer_el is not None:
                host = computer_el.text

            channel_el = system.find("e:Channel", ns)
            if channel_el is not None:
                channel = channel_el.text

            time_el = system.find("e:TimeCreated", ns)
            if time_el is not None:
                timestamp = time_el.attrib.get("SystemTime")

        if event_data is not None:
            for data_el in event_data.findall("e:Data", ns):
                name = data_el.attrib.get("Name")
                value = data_el.text
                if name:
                    fields[name] = value

        return ParsedEvent(
            source=str(file_path),
            parser_type=self.parser_type,
            timestamp=timestamp,
            host=host,
            program=provider,
            pid=None,
            message=f"Windows Event ID {event_id}" if event_id is not None else "Windows Event",
            event_id=event_id,
            fields={
                "channel": channel,
                "record_number": record_number,
                **fields,
            },
        )    
    
    @staticmethod
    def _strip_ns(tag: str) -> str:
        # Strips the unwanted XML namespace from the tag.
        if "}" in tag:
            return tag.split("}", 1)[1]
        return tag