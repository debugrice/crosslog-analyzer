
import gzip
from pathlib import Path
from models.parsed_event import ParserErrorEvent
from abc import ABC, abstractmethod

class BaseLineParser:
    parser_type = "base"
    
    def parse_file(self, file_path: Path):
        """Base parse file method. Opens the file and reads one line at a time.

        Args:
            file_path (Path): Path object to the input file.

        Yields:
            _type_: ParseEvent or ParseErrorEvent message
        """
        # Added to open archived gzip files
        if file_path.suffix == ".gz":
            f = gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
        else:
        # Standard text file open statement
            f = open(file_path, "r", encoding="utf-8", errors="replace")

        with f:
            for line_number, line in enumerate(f, start=1):
                raw = line.rstrip("\n")
                
                if not raw.strip():
                    continue
                try:
                    yield self.parse_line(
                        raw,
                        source=str(file_path),
                        line_number=line_number,
                    )
                except Exception as exc:
                    yield ParserErrorEvent(
                        source=str(file_path),
                        parser_type=self.parser_type,
                        raw_record=raw,
                        error=str(exc),
                        line_number=line_number,
                    )
    @abstractmethod
    def parse_line(self, line: str, source: str, line_number: int | None = None):
        """
            Abstract method which must be implemented by the child classes
        Args:
            line (str): text line of from the file
            source (str): file path of the source
            line_number (int | None, optional): Line number from the source Defaults to None.
        """
        pass