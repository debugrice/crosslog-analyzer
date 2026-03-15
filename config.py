
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class CrossLogPipelineConfig:
    """Data class used to hold the user configuration items.
    """
    input_paths: List[Path]
    input_format: str = "auto"
    recursive: bool = False
    report_mode: str = "summary"
    fail_fast: bool = False
    summary_output_path: Optional[Path] = None
    findings_csv_path: Optional[Path] = None