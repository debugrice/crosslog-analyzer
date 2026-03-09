This project implements the CrossLog Analyzer, a tool for parsing syslog and Windows Event Logs. It supports RFC 3164 and RFC 5424 syslog formats, as well as Windows EVTX and XML event log files.

Install the required packages:
pip install -r requirements.txt

To print the help menu: 

python crosslog.py --help

To parse a single file:

python crosslog.py sample.xml

To parse multiple files:

python crosslog.py sample-1.xml sample-2.xml sample-3.xml

