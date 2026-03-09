"""
File: crosslog/models/run_result.py
Author: Danny Ray
Date: 03/07/2026
Description: Data class for storing the results from the run.
"""
from dataclasses import dataclass, field
from typing import Any

@dataclass
class RunResult:
    """Data class used to hold the results from the CrossLogPipeline.
    """
    files_processed: int    = 0
    fatal_errors: int       = 0
    
    normalized_events: list = field(default_factory=list)
    findings: list          = field(default_factory=list)
    
    parser_errors: list     = field(default_factory=list)
    normalization_errors: list = field(default_factory=list)
    detection_errors: list  = field(default_factory=list)
    file_errors: list       = field(default_factory=list)
    
    def total_events(self) -> int:
        """Getter method to return the total_events

        Returns:
            int: Total number of normalized events.
        """
        return len(self.normalized_events)

    def total_findings(self) -> int:
        """Getter method used to return the total findings.

        Returns:
            int: Total findings from the run.
        """
        return len(self.findings)

    def total_parser_errors(self) -> int:
        """Getter method for the total parser errors.

        Returns:
            int: Total number of parser errors.
        """
        return len(self.parser_errors)

    def total_normalization_errors(self) -> int:
        """Getter method for the total normalization errors.

        Returns:
            int: Total number of normalization errors.
        """
        return len(self.normalization_errors)

    def total_detection_errors(self) -> int:
        """Getter method for the total number of detection errors.

        Returns:
            int: Total number of detection errors.
        """
        return len(self.detection_errors)

    def total_file_errors(self) -> int:
        """Getter method for the total number of file errors.

        Returns:
            int: Total number of file errors.
        """
        return len(self.file_errors)

    def has_errors(self) -> bool:
        """Method used to determine if any type of error was flagged.

        Returns:
            bool: True if an error was detected; False if no errors were detected.
        """
        return any([
            self.fatal_errors > 0,
            self.parser_errors,
            self.normalization_errors,
            self.detection_errors,
            self.file_errors,
        ])
        
    def add_file_error(self, source: str, stage: str, error: str) -> None:
        """Method used to add file errors to the results list.

        Args:
            source (str): File that caused the error.
            stage (str): At what stage in the pipeline did the failure occur.
            error (str): Error message provided by the exception.
        """
        self.file_errors.append({
            "source": source,
            "stage": stage,
            "error": error,
        })

    def add_normalization_error(self, source: str, stage: str, error: str, event: Any | None = None) -> None:
        """Method used to add normalization errors to the results list.

        Args:
            source (str): File that caused the error. 
            stage (str): At what stage in the pipeline did the failure occur.
            error (str): At what stage in the pipeline did the failure occur.
            event (Any | None, optional): Event information if available. Defaults to None.
        """
        self.normalization_errors.append({
            "source": source,
            "stage": stage,
            "error": error,
            "event": event,
        })

    def add_detection_error(self, source: str, stage: str, error: str, event: Any | None = None) -> None:
        """Method used to add detection errors to the results list.

        Args:
           source (str): File that caused the error. 
            stage (str): At what stage in the pipeline did the failure occur.
            error (str): At what stage in the pipeline did the failure occur.
            event (Any | None, optional): Event information if available. Defaults to None.
        """
        self.detection_errors.append({
            "source": source,
            "stage": stage,
            "error": error,
            "event": event,
        })
  
    def add_parser_error(self, source: str, event: Any | None = None):
        """Method used to add parser error messages to the list.

        Args:
            source (str): File that caused the error.
            event (Any | None, optional): Event message if available. Defaults to None.
        """
        self.parser_errors.append({
            "source": source,
            "event": event,            
        })