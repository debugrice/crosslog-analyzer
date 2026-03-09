"""
File: crosslog/parsers/rfc3164.py
Author: Danny Ray
Date: 03/07/2026
Description: RFC3164 Parser used to extract BSD style syslog files.
"""
import re

from models.parsed_event import ParsedEvent
from parsers.baseline_parser import BaseLineParser

# Matching REGEX constant file
RFC3164_LINE_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:]+):\s*"
    r"(?P<message>.*)$"
)

class RFC3164Parser(BaseLineParser):
    """BSD class implementation for extract text syslogs.
    Args:
        BaseLineParser (_type_): Parent base logger class.
    """
    parser_type = "rfc3164"
    
    def parse_line(self, line: str, 
                   source: str, 
                   line_number: int | None = None ) -> ParsedEvent:
        """Overridden method to extract and parse each text line from the file.

        Args:
            line (str): Line of data from the text file.
            source (str): File providing the data.
            line_number (int | None, optional): Line number. Defaults to None.

        Raises:
        ValueError: If the parser fails, it will throw an exception.

        Returns:
            ParsedEvent: Parsed object from the provided string.
        """
        # Determine if the text string matches RFC 3164
        ret_line = RFC3164_LINE_RE.match(line)
        
        if not ret_line:
            raise ValueError("Line is not valid RFC3164")
        
        # pri and tag are not guaranteed to be in the file.
        pri = ret_line.group("pri")
        tag = ret_line.group("tag")
        
        program = tag
        pid = None
        
        # Need this regex to extract the program and pid number.
        tag_match = re.match(r"^(?P<program>[^\[]+)(?:\[(?P<pid>\d+)\])?$", tag)
        if tag_match:
            program = tag_match.group("program")
            if tag_match.group("pid"):
                pid = int(tag_match.group("pid"))
                
        facility = None
        severity = None
        
        if pri is not None:
            pri_val = int(pri)
            facility = pri_val // 8
            severity = pri_val % 8
            
        return ParsedEvent(
            source=source,
            parser_type=self.parser_type,
            timestamp=ret_line.group("timestamp"),
            program=program,
            host=ret_line.group("host"),
            pid=pid,
            message=ret_line.group("message"),
            severity=severity,
            facility=facility,
            fields={"line_number": line_number},   
        )