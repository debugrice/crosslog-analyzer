This project implements the CrossLog Analyzer, a tool for parsing syslog and Windows Event Logs. It supports RFC 3164 and RFC 5424 syslog formats, as well as Windows EVTX and XML event log files.

Install the required packages:
pip install -r requirements.txt

```text
To print the help menu: 

python crosslog.py --help
  usage: crosslog [-h] [--format {auto,rfc3164,rfc5424,evtx,xml}] [--recursive] [--fail-fast] [--mode {summary,full}] [--summary-out SUMMARY_OUT] [--findings-csv FINDINGS_CSV] inputs [inputs ...]

Cross Platfrom log analyzer program for detecting cybersecurity events from user provided log files.

positional arguments:
  inputs                One or more log files or directories containting log files.

options:
  -h, --help            show this help message and exit
  --format {auto,rfc3164,rfc5424,evtx,xml}
                        Force a parser format, or use the default auto-detect.
  --recursive           Recursively search directories for log files.
  --fail-fast           Stop processing if an exception is detected.
  --mode {summary,full}
                        Print console output as summary or full. Default=summary
  --summary-out SUMMARY_OUT
                        Write the report summary to a text file.
  --findings-csv FINDINGS_CSV
                        Write the findings to a CSV file.

To parse a single file:

python crosslog.py sample.xml

To parse multiple files:

python crosslog.py sample-1.xml sample-2.xml sample-3.xml

To parse a single directory:

python crosslog.py sub_directory_1

To parse a single directory recursively:

python crosslog.py sub_directory_1 --recursive
