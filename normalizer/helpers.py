"""
File: crosslog/normalizer/helpers.py
Author: Danny Ray
Date: 03/07/2026
Description: Helper functions for cleaning up the different event fields.
"""
def normalize_host(host: str) -> str:
    """Function used to reformat strings.
    
    Args:
        host (str): String to the reformated.

    Returns:
        str: String with removed whitespaces and lower case.
    """
    if not host:
        return None
    return host.strip().lower()


def normalize_program(program: str, parser_type: str) -> str:
    """Function to reformat the program string extracted by the parser.

    Args:
        program (str): String name of the program extracted by the parser.
        parser_type (str): Name of the parser providing the program name.

    Returns:
        str: Reformatted program name.
    """
    if not program:
        return None
    value = program.strip()
    
    # List of parse types. Remapping the windows security label.
    if parser_type in {"evtx", "xml", "windows_xml"}:
        mapping = {
            "Microsoft-Windows-Security-Auditing": "windows-security",
        }
        return mapping.get(value, value.lower())
    
    return value.lower()
        
def normalize_message(message: str) -> str:
    """Function to help clean up the extracted message string.

    Args:
        message (str): Parser extracted message.

    Returns:
        str: Normalize string with whitespaces removed and collapsed to a single line.
    """
    if not message:
        return ""
    return " ".join(message.strip().split())
