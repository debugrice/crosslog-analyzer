"""
File: crosslog/ingest/file_loader.py
Author: Danny Ray
Date: 03/07/2026
Description: Functions used to load the user input.
"""
from pathlib import Path
from typing import Iterable, List

# List of supported file extensions
# NOTE Each file extension must have a parser.
SUPPORTED_EXTENSIONS = {
    ".log",
    ".txt",
    ".evtx",
    ".xml"
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
    """Helper function used to identify supported file types.

    Args:
        file_path (Path): File path object

    Returns:
        bool: True if contained within the SUPPORTED_EXTENSIONS
    """
    if (file_path.suffix.lower() in SUPPORTED_EXTENSIONS) or (file_path.suffix == ""):
        return True
    
    return False