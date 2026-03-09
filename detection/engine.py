"""
File: crosslog/detection/engine.py
Author: Danny Ray
Date: 03/07/2026
Description: Functions used to process all detection rules.
"""
from detection.rules.linux_auth import RULES as LINUX_AUTH_RULES
from detection.rules.windows_auth import RULES as WINDOWS_AUTH_RULES

# List of rules to process
# TODO Add more rules to this section.
RULES = (
    LINUX_AUTH_RULES
    + WINDOWS_AUTH_RULES
)

def detect(event):
    """Main function used to drive the detection stage.

    Args:
        event (Event): Event object from the normalization stage.

    Returns:
        List[Finding]: List of findings detected from the provided rules.
    """
    findings = []

    # List of rules to loop through and evaluate the event against.
    for rule in RULES:
        finding = rule(event)
        if finding is not None:
            findings.append(finding)

    return findings