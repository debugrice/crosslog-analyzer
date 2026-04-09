
import argparse
import sys

from pathlib import Path
from typing import List

from output.console import print_report
from output.text_report import write_summary_report
from output.findings_csv_report import write_findings_csv
from services.pipeline_service import run_pipeline
from web.app import app

def build_argparser() -> argparse.ArgumentParser:
    """"
    Builds the argument parser for the cross log parser.
    
    Returns:
        argparse.ArgumentParser: buildin argparser with customized application settings.
    """
    p = argparse.ArgumentParser(prog="crosslog",
                                description=(
                                    "Cross Platfrom log analyzer program for detecting "
                                    "cybersecurity events from user provided log files.")
                                )
    # User can input single files or directories (if directory check the recursive option).
    p.add_argument(
        "inputs",
        nargs="+",
        help="One or more log files or directories containting log files."
    )
    # User can bypass the auto check and set the parser type.
    p.add_argument(
        "--format",
        choices=[ "auto","rfc3164","rfc5424", "evtx", "xml", "auditd", "journal" ],
        default="auto",
        help="Force a parser format, or use the default auto-detect."
    )
    # If user passes this option, then loop through all discovered directories.
    p.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively search directories for log files."
    )
    # If user passes this option, then the pipeline terminates when an error is detected.
    p.add_argument(
        "--fail-fast",
        default=False,
        action="store_true",
        help="Stop processing if an exception is detected."
    )
    # This option is for print the console report. Options are summary or full.
    p.add_argument(
        "--mode",
        choices=["summary","full"],
        default="summary",
        help="Print console output as summary or full. Default=summary"
    )
    # This option allows the user write the summary report to a file.
    p.add_argument(
        "--summary-out",
        type=Path,
        help="Write the report summary to a text file."
    )
    # This option allows the user to write the detail findings to a CSV file.
    p.add_argument(
        "--findings-csv",
        type=Path,
        help="Write the findings to a CSV file."
    )
    # Only report findings at or above this severity level.
    p.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        dest="min_severity",
        help="Only report findings at or above this severity level (default: info).",
    )
    # Added to launch the flask api as an option
    p.add_argument(
        "--web",
        action="store_true",
        help="Start the web interface instead of command-line mode."
    )
    # Identify the network interface for the flask api
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Web host address. Default=127.0.0.1"
    )
    # Identify the TCP port to bind toeh flask api to
    p.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Web port. Default=5000"
    )
    # Debug option for the flask api
    p.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Enable Flask debug mode."
    )

    return p

def validate_inputs(raw_inputs: List[str]) -> List[Path]:
    """
    Extracts the user input files into a list of Path objects.

    Args:
        raw_inputs (List[str]): list of raw strings that need to converted Path objects

    Returns:
        List[Path]: List of file system Path objects
    """
    paths = []
    for p in raw_inputs:
        paths.append(Path(p))
    
    # Check to see if all the input strings are valid.
    missing = []
    for p in paths:
        if not p.exists():
            missing.append(p)
    # TODO: Verify the plan would be to stop on missing input.
    if missing:
        for path in missing:
            print(f"[ERROR]: Input does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    
    return paths

def run_web(host: str, port: int, debug: bool) -> int:
    """Function used to launch the flask api.

    Args:
        host (str): Host IP address or network interface to use
        port (int): TCP port to bind the flask api
        debug (bool): Debug mode option for the flask api

    Returns:
        int: Exit integer value
    """
    
    app.run(host=host, port=port, debug=debug)
    
    return 0  
   
def main() -> int:
    """Main function for processing the log files. 
    This will contain the pipline fascade class.

    Args:
        None

    Returns:
        int: Integer value for exiting the system.
    """
    args_parser = build_argparser()
    args        = args_parser.parse_args(sys.argv)
    
    try:
        
        # Check if the user wishes to run the flask api
        if args.web:
            return run_web(args.host, args.port, args.debug)
        
        # If CLI, the user must provide input
        if not args.inputs:
                args_parser.print_help()
                return 1

        # Files that were discovered by the user input
        input_paths = validate_inputs(args.inputs)

        # Pipeline call to process all the files
        results, files, config = run_pipeline(
            input_paths=input_paths,
            input_format=args.format,
            recursive=args.recursive,
            fail_fast=args.fail_fast,
            report_mode=args.mode,
            summary_output_path=args.summary_out,
            findings_csv_path=args.findings_csv,
            min_severity=args.min_severity,
        )

        # Console output of the results
        print_report(results, report_mode=config.report_mode)

        # Check to write the summary report
        if config.summary_output_path:
            write_summary_report(
                result=results,
                output_path=config.summary_output_path
            )
        # Check to write the CSV file
        if config.findings_csv_path:
            write_findings_csv(
                result=results,
                output_path=config.findings_csv_path
            )

        return 0

    except KeyboardInterrupt:
        print("Program interrupted by user.")
        return 130
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
    return 1

if __name__ == "__main__":
    sys.exit(main())
