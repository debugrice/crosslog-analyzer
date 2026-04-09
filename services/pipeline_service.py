from pathlib import Path
from typing import List, Optional

from config import CrossLogPipelineConfig
from crosslogpipeline import CrossLogPipeline
from ingest.file_loader import discover_input_files
from models.run_result import RunResult

def run_pipeline(
    input_paths: List[Path],
    input_format: str = "auto",
    recursive: bool = False,
    fail_fast: bool = False,
    report_mode: str = "summary",
    summary_output_path: Optional[Path] = None,
    findings_csv_path: Optional[Path] = None,
    min_severity: str = "info",
) -> tuple[RunResult, List[Path], CrossLogPipelineConfig]:
    """Extracted function used to consolidate the pipeline for the both the Flask API and CLI.

    Args:
        input_paths (List[Path]): Provided list of valid input files.
        input_format (str, optional): Optional parser override. Defaults to "auto".
        recursive (bool, optional): Notifies the file discovery to recursive look for files. Defaults to False.
        fail_fast (bool, optional): Stops the pipeline if a problem is detected. Defaults to False.
        report_mode (str, optional): Limits the output text to either full or summary. Defaults to "summary".
        summary_output_path (Optional[Path], optional): Location to save the summary output. Defaults to None.
        findings_csv_path (Optional[Path], optional): Location to save the CSV file. Defaults to None.
        min_severity (str, optional): Limits the findings output. Defaults to "info".

    Raises:
        ValueError: Log files that are unsupported will trigger this exception

    Returns:
        _type_: 
    """
    config = CrossLogPipelineConfig(
        input_paths=input_paths,
        input_format=input_format,
        recursive=recursive,
        fail_fast=fail_fast,
        report_mode=report_mode,
        summary_output_path=summary_output_path,
        findings_csv_path=findings_csv_path,
        min_severity=min_severity,
    )

    files = discover_input_files(input_paths, recursive=recursive)
    
    if not files:
        raise ValueError("No supported input log files found.")

    pipeline = CrossLogPipeline(config=config)
    result = pipeline.run(files=files)

    return result, files, config