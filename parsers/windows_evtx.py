
from pathlib import Path
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser
from models.parsed_event import ParsedEvent, ParserErrorEvent

class EvtxParser:
    """Implementation of the Windows EVTX file parser

    Yields:
        ParsedEvent|ParsedErrorEvent: Yields messages extracted from the file. 
    """
    parser_type = "evtx"
    
    def parse_file(self, file_path: Path):
        """Method parses the EVTX Windows binary file.

        Args:
            file_path (Path): String path object to the binary file.

        Yields:
            _type_: Produces the ParsedEvent object
        """
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
        # data is a string of XML that must be parsed
        xml_text = record.get("data") or ""
        parsed = self._extract_xml_fields(xml_text)

        return ParsedEvent(
            source=str(file_path),
            parser_type=self.parser_type,
            timestamp=record.get("timestamp"),
            host=parsed.get("computer"),
            program=parsed.get("provider"),
            pid=parsed.get("pid"),
            message=parsed.get("message") or "Windows Event Log",
            event_id=int(parsed.get("event_id")),
            fields={
                "channel": parsed.get("channel"),
                "provider": parsed.get("provider"),
                "computer": parsed.get("computer"),
                "event_record_id": record.get("event_record_id"),
                "keywords": parsed.get("keywords"),
                "level": parsed.get("level"),
                "opcode": parsed.get("opcode"),
                "task": parsed.get("task"),
                "system_time": parsed.get("system_time"),
                "thread_id": parsed.get("thread_id"),
                "event_data": parsed.get("event_data", {}),
                "user_data": parsed.get("user_data", {}),
                "raw": xml_text,
            },
        )

    def _extract_xml_fields(self, xml_text: str) -> dict:
        """Parse the XML string from record['data'] and extract useful fields.

        Args:
            xml_text (str): XML data from the record

        Returns:
            dict: Extract dictionary of the items in the XML 
        """
        if not xml_text:
            return {}

        root = ET.fromstring(xml_text)

        result = {
            "event_id": None,
            "provider": None,
            "computer": None,
            "channel": None,
            "pid": None,
            "thread_id": None,
            "system_time": None,
            "level": None,
            "task": None,
            "opcode": None,
            "keywords": None,
            "message": None,
            "event_data": {},
            "user_data": {},
        }

        # Top level tree for the Windows Record
        system = self._find_child(root, "System")
        if system is not None:
            for child in system:
                tag = self._strip_ns(child.tag)

                if tag == "EventID":
                    result["event_id"] = child.text

                elif tag == "Provider":
                    result["provider"] = child.attrib.get("Name")

                elif tag == "Computer":
                    result["computer"] = child.text

                elif tag == "Channel":
                    result["channel"] = child.text

                elif tag == "Execution":
                    result["pid"] = (
                        child.attrib.get("ProcessID")
                        or child.attrib.get("ProcessId")
                        or child.attrib.get("processid")
                        or child.attrib.get("process_id")
                    )
                    result["thread_id"] = (
                        child.attrib.get("ThreadID")
                        or child.attrib.get("ThreadId")
                        or child.attrib.get("threadid")
                        or child.attrib.get("thread_id")
                    )

                elif tag == "TimeCreated":
                    result["system_time"] = child.attrib.get("SystemTime")

                elif tag == "Level":
                    result["level"] = child.text

                elif tag == "Task":
                    result["task"] = child.text

                elif tag == "Opcode":
                    result["opcode"] = child.text

                elif tag == "Keywords":
                    result["keywords"] = child.text

        event_data = self._find_child(root, "EventData")
        if event_data is not None:
            for data_elem in event_data:
                if self._strip_ns(data_elem.tag) != "Data":
                    continue

                name = data_elem.attrib.get("Name")
                value = data_elem.text or ""

                if name:
                    result["event_data"][name] = value

        user_data = self._find_child(root, "UserData")
        if user_data is not None:
            result["user_data"] = self._xml_element_to_dict(user_data)

        # Optional message data
        if result["event_data"]:
            result["message"] = "; ".join(
                f"{k}={v}" for k, v in result["event_data"].items()
            )

        return result

    def _find_child(self, parent, child_name: str):
        """Extracts the XML tags from the tree.

        Args:
            parent (_type_): XML Parent tag
            child_name (str): XML child string tag name

        Returns:
            _type_: Child tag else None
        """
        for child in parent:
            if self._strip_ns(child.tag) == child_name:
                return child
        return None

    def _strip_ns(self, tag: str) -> str:
        """Private method to remove newline spaces from the string.

        Args:
            tag (str): string tag name for the XML element

        Returns:
            str: string with newline removed
        """
        return tag.split("}", 1)[1] if "}" in tag else tag

    def _xml_element_to_dict(self, elem):
        """Convert the xml elements to a dictionary

        Args:
            elem (_type_): XML element data

        Returns:
            _type_: Dictionary of the XML values
        """
        result = {}

        for child in elem:
            child_tag = self._strip_ns(child.tag)

            if len(child):
                value = self._xml_element_to_dict(child)
            else:
                value = child.text or ""

            if child.attrib:
                value = {
                    "_text": value,
                    "_attributes": dict(child.attrib),
                }

            if child_tag in result:
                if not isinstance(result[child_tag], list):
                    result[child_tag] = [result[child_tag]]
                result[child_tag].append(value)
            else:
                result[child_tag] = value

        return result