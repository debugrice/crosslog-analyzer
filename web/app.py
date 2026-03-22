"""
Flask web application entry point for CrossLog Analyzer.

Provides a browser-based interface for uploading log files and viewing
pipeline results without using the command-line interface.
"""

import sys
import tempfile
import shutil
from pathlib import Path
from collections import Counter, defaultdict
from flask import Flask, render_template, request

# Insert the project root into sys.path so that pipeline modules are
# importable when the application is launched from the web/ subdirectory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import CrossLogPipelineConfig
from crosslogpipeline import CrossLogPipeline
from ingest.file_loader import discover_input_files

app = Flask(__name__)

# Limit total upload size per request to prevent excessively large submissions.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB

# Custom Jinja2 filter that extracts the final component of a file path string.
app.jinja_env.filters["basename"] = lambda p: Path(p).name


@app.route("/")
def index():
    """Render the file upload form.

    Returns:
        Response: Rendered index.html template.
    """
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Accept uploaded log files, execute the CrossLog pipeline, and render results.

    Reads uploaded files and pipeline options from the multipart POST request,
    writes files to an isolated temporary directory, runs the full parse-normalize-
    detect pipeline, then constructs the template context from the resulting
    RunResult before cleaning up all temporary files.

    Returns:
        Response: Rendered results.html on success, or index.html with an error
                  message if validation fails or the pipeline raises an exception.
    """
    uploaded_files = request.files.getlist("logfiles")
    input_format   = request.form.get("format", "auto")
    fail_fast      = request.form.get("fail_fast") == "on"

    # Reject the request early if no files were included in the form submission.
    if not uploaded_files or all(f.filename == "" for f in uploaded_files):
        return render_template("index.html", error="No files were uploaded.")

    # Create an isolated temporary directory scoped to this single request.
    tmp_dir = Path(tempfile.mkdtemp())
    try:
        # Write each uploaded file to the temporary directory and record its path.
        saved_paths = []
        for upload in uploaded_files:
            if upload.filename:
                dest = tmp_dir / upload.filename
                upload.save(dest)
                saved_paths.append(dest)

        config = CrossLogPipelineConfig(
            input_paths=saved_paths,
            input_format=input_format,
            fail_fast=fail_fast,
        )

        # Filter saved paths to only those with extensions the pipeline supports.
        files = discover_input_files(saved_paths, recursive=False)
        if not files:
            return render_template(
                "index.html",
                error="No supported log files found in the upload (supported: .log, .txt, .evtx, .xml)."
            )

        # Execute the full parse → normalize → detect pipeline.
        pipeline = CrossLogPipeline(config=config)
        result   = pipeline.run(files=files)

        # Aggregate findings by severity using the standard display priority order.
        severity_counts = Counter(
            (f.severity or "unknown").lower() for f in result.findings
        )
        category_counts = Counter(
            (f.category or "unknown").lower() for f in result.findings
        )

        severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
        severity_rows  = [(s, severity_counts.get(s, 0)) for s in severity_order if severity_counts.get(s, 0)]
        category_rows  = sorted(category_counts.items())

        # Build per-file summary rows for the Files Processed and Events Parsed stat card drawers.
        events_by_source   = Counter(e.source for e in result.normalized_events)
        parser_by_source   = {e.source: e.parser_type for e in result.normalized_events}
        findings_by_source = Counter(f.source for f in result.findings)
        file_rows = [
            {
                "name":     f.name,
                "events":   events_by_source.get(str(f), 0),
                "parser":   parser_by_source.get(str(f), "—"),
                "findings": findings_by_source.get(str(f), 0),
            }
            for f in files
        ]

        # Build a labelled breakdown of each error category for the Errors stat card.
        error_breakdown = [
            ("File errors",          result.total_file_errors()),
            ("Parser errors",        result.total_parser_errors()),
            ("Normalization errors", result.total_normalization_errors()),
            ("Detection errors",     result.total_detection_errors()),
            ("Fatal errors",         result.fatal_errors),
        ]

        return render_template(
            "results.html",
            result=result,
            severity_rows=severity_rows,
            category_rows=category_rows,
            file_rows=file_rows,
            error_breakdown=error_breakdown,
        )

    except Exception as exc:
        return render_template("index.html", error=f"Pipeline error: {exc}")
    finally:
        # Remove the temporary directory regardless of whether the pipeline succeeded.
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    app.run(debug=True)
