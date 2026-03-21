
import re
import gzip
from pathlib import Path
from parsers.windows_evtx import EvtxParser
from parsers.windows_xml import WindowsXmlParser
from parsers.rfc3164 import RFC3164Parser
from parsers.rfc5424 import RFC5424Parser

# Regex string object for identifying RFC 3164 and RFC 5424
# TODO Additional text based parsers should have matching patterns
RFC3164_RE = re.compile(r"^(<\d{1,3}>)?[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s")
RFC5424_RE = re.compile(r"^<\d{1,3}>[1-9]\d{0,2}\s")


def check_for_rfc5424(line: str) -> bool:
    """Regex to check if the string pattern matches the RFC 5424

    Args:
        line (str): String to be checked for the matching RFC5424 pattern

    Returns:
        bool: True if the string matches the RFC5424 or False if it does not
    """
    return bool(RFC5424_RE.match(line))

def check_for_rfc3164(line: str) -> bool:
    """Regex to check if the string patten matches the RFC 3164.

    Args:
        line (str): String to be checked for the matching RFC3164 pattern

    Returns:
        bool: True if the string matches the RFC3164 or False if it does not
    """
    return bool(RFC3164_RE.match(line))

def check_for_windows_event_xml(file_path):
    """Function used to check if the file matches the Windows XML event type.

    Args:
        file_path (Path): Path object to the XML file input.

    Returns:
        bool: True if the XML file matches Windows XML Events or False if it does not.
    """
    try:
        # Open the file read only
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            # Basically check the first few lines for the xml schema
            for _ in range(20):
                line = f.readline()
                if not line:
                    break

                text = line.strip()
                if not text:
                    continue

                # TODO This could be improved for better XML schema matching
                if "<Event " in text or "<Events>" in text or 'http://schemas.microsoft.com/win/2004/08/events/event' in text:
                    return True
    except OSError:
        return False
    
def get_parser_for_file(file_path: Path, forced_format: str="auto") -> None:
    """Function used to determine the type of parser needed.

    Args:
        file_path (Path): Path object to the log file being parsed.
        forced_format (str, optional): Input option to force parsing type. Defaults to "auto".

    Raises:
        ValueError: If the parser can not be determined. Then it will fail immediately.

    Returns:
        Parser Object: Returns the parser needed to parse the input file.
    """
    # If the user is overriding the parser selection, return what they want.
    if forced_format != "auto":
        return forced_parser(forced_format)

    # EvtxParser is easy if the file extension matches Windows binary file types.    
    if file_path.suffix.lower() == ".evtx":
        return EvtxParser()
    # WindowsXmlParser is easy if the file extension matches.
    if file_path.suffix.lower() == ".xml" and \
        check_for_windows_event_xml(file_path=file_path):
        return WindowsXmlParser()
    
    # Linux Syslog types are text strings. We must extract and test.    
    first_line = get_first_nonempty_line(file_path)
    # Must have something in it.
    if first_line:
        if check_for_rfc5424(first_line):
            return RFC5424Parser()
        if check_for_rfc3164(first_line):
            return RFC3164Parser()
        
    raise ValueError(f"Could not determine the parser type for file: {file_path}")

def forced_parser(forced_format:str) -> None:
    """Helper function that enables the user to force a parser type.

    Args:
        forced_format (str): Parser user options.

    Raises:
        ValueError: Throws an error if the parser type is unknown.

    Returns:
        ParserObject: Dynamic parser type if discovered. 
    """
    # List of available parsers
    # TODO Update as new parsers are added
    parser_map = {
        "rfc3164": RFC3164Parser,
        "rfc5424": RFC5424Parser,
        "evtx": EvtxParser,
        "xml": WindowsXmlParser,
    }
    
    # Use the dictionary map to extract the type of parser
    parser_cls = parser_map.get(forced_format)
    
    # Ensure the parser was discovered
    if parser_cls is None:
        raise ValueError(f"Unsupported forced format: {forced_format}")
    
    # Call the constructor and return
    return parser_cls()

def get_first_nonempty_line(file_path: str) -> str:
    """Function used to extract the first non-empty string line from the file.

    Args:
        file_path (str): File name to be opened.

    Returns:
        str: First line of the file that is not empty.
    """
    try:
        # gzip files need to be opened differently that standard text files
        if file_path.suffix == ".gz":
            f = gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
        else:
        # Standard text file open statement
            f = open(file_path, "r", encoding="utf-8", errors="replace")

        with f:
            for line in f:
                line = line.strip()
                if line:
                    return line
    except OSError:
        return None
    return None

