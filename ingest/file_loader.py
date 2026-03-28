
from pathlib import Path
from typing import Iterable, List

# List of supported file extensions
# NOTE Each file extension must have a parser.
SUPPORTED_EXTENSIONS = {
    ".log",
    ".txt",
    ".evtx",
    ".xml",
    ".gz",
    ".json"
}

def discover_input_files( input_paths: Iterable[Path],
                        recursive: bool = False) -> List[Path]:
    """
    Function used to discover all files within the provided path.
    Args:
        input_paths (Iterable[Path]): List of paths provided to search
        recursive (bool, optional): Variable used to control recursive lookup. Defaults to False.

    Returns:
        List[Path]: Returns a list of support file types in a Path object.
    """
    discovered: List[Path] = []
    
    for path in input_paths:
        
        # Direct file input 
        if path.is_file():
            discovered.append(path) if is_supported_file(path) else None
            continue
        # Check if its a directory
        if path.is_dir():
            # If the recursive flag was set by user
            if recursive:
                files = path.rglob("*")
            else:
                files = path.glob("*")
            # Grab all the files if they are log files (or extensions match)
            for file in files:
                if file.is_file() and is_supported_file(file):
                    discovered.append(file)
    
    return discovered

def is_supported_file(file_path: Path) -> bool:
    """Helper function used to determine if the file is a supported type.

    Args:
        file_path (Path): File path object containing the filename

    Returns:
        bool: True if supported; False if not supported
    """
    suffixes = file_path.suffixes

    # No suffix at all - Standard syslog files
    if not suffixes:
        return True

    # Normal supported extensions
    if file_path.suffix in SUPPORTED_EXTENSIONS:
        return True

    # Looks for the numbered digits at the end of the rotated logs (syslog.1 or auth.log.2)
    if suffixes[-1][1:].isdigit():
        return True

    # Gzipped rotated logs like syslog.1.gz or auth.log.2.gz
    if len(suffixes) >= 2 and suffixes[-1] == ".gz":
        if suffixes[-2][1:].isdigit() or suffixes[-2] in {".log", ".txt"}:
            return True

    return False