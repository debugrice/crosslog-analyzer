"""
File: crosslog/output/console.py
Author: Danny Ray
Date: 03/08/2026
Description: Functions used to print the report via the console.
"""
from collections import Counter

from models.run_result import RunResult

def print_report(result: RunResult, report_mode: str = "summary") -> None:
    """
    Print a console report for a pipeline run.
    """

    # Private summary printer function
    _print_summary(result)

    # If the user selected the full print, print the detailed data
    if report_mode == "full":
        _print_findings(result)
        _print_errors(result)


def _print_summary(result: RunResult) -> None:
    """Private function for printing the summary data.

    Args:
        result (RunResult): Results from the pipeline run.
    """
    print("\n=== CrossLog Report ===")
    print(f"Files processed:        {result.files_processed}")
    print(f"Normalized events:      {result.total_events()}")
    print(f"Findings:               {result.total_findings()}")
    print(f"Parser errors:          {result.total_parser_errors()}")
    print(f"Normalization errors:   {result.total_normalization_errors()}")
    print(f"Detection errors:       {result.total_detection_errors()}")
    print(f"File errors:            {result.total_file_errors()}")
    print(f"Fatal errors:           {result.fatal_errors}")

    # If there are findings print them
    if result.findings:
        #TODO track unknown items - These need to beh identified
        severity_counts = Counter(
            (finding.severity or "unknown").lower()
            for finding in result.findings
        )

        print("\nFindings by severity:")
        #TODO unknown types need to be reclassified when detected
        for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
            count = severity_counts.get(severity, 0)
            if count:
                print(f"  {severity:<8} {count}")

        #TODO unknown needs to be identified
        category_counts = Counter(
            (finding.category or "unknown").lower()
            for finding in result.findings
        )

        print("\nFindings by category:")
        for category, count in sorted(category_counts.items()):
            print(f"  {category:<15} {count}")


def _print_findings(result: RunResult) -> None:
    """Private function to print the detail findings

    Args:
        result (RunResult): Results from the pipeline run.
    """
    print("\n=== Findings ===")

    if not result.findings:
        print("No findings detected.")
        return

    for index, finding in enumerate(result.findings, start=1):
        print(f"\n[{index}] {finding.title}")
        print(f"  Rule ID:    {finding.rule_id}")
        print(f"  Severity:   {finding.severity}")
        print(f"  Category:   {finding.category}")
        print(f"  Host:       {finding.host}")
        print(f"  Timestamp:  {finding.timestamp}")
        print(f"  Source:     {finding.source}")
        print(f"  Event Type: {finding.event_type}")
        print(f"  Message:    {finding.message}")

        if finding.fields:
            print("  Fields:")
            for key, value in sorted(finding.fields.items()):
                print(f"    {key}: {value}")


def _print_errors(result: RunResult) -> None:
    """Function for printing the errors.

    Args:
        result (RunResult): Results from the pipeline run.
    """
    if not result.has_errors():
        return

    print("\n=== Errors ===")

    if result.file_errors:
        print("\n-- File Errors --")
        for error in result.file_errors:
            print(f"  Source: {error.get('source')}")
            print(f"  Stage:  {error.get('stage')}")
            print(f"  Error:  {error.get('error')}")
            print()

    if result.parser_errors:
        print("\n-- Parser Errors --")
        for error in result.parser_errors:
            print(f"  Source:      {error.source}")
            print(f"  Line Number: {error.line_number}")
            print(f"  Parser:      {error.parser_type}")
            print(f"  Error:       {error.error}")
            print(f"  Raw:         {error.raw_record}")
            print()

    if result.normalization_errors:
        print("\n-- Normalization Errors --")
        for error in result.normalization_errors:
            print(f"  Source: {error.get('source')}")
            print(f"  Stage:  {error.get('stage')}")
            print(f"  Error:  {error.get('error')}")
            print()

    if result.detection_errors:
        print("\n-- Detection Errors --")
        for error in result.detection_errors:
            print(f"  Source: {error.get('source')}")
            print(f"  Stage:  {error.get('stage')}")
            print(f"  Error:  {error.get('error')}")
            print()