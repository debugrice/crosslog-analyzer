
from detection.rules.linux_auth import RULES as LINUX_AUTH_RULES
from detection.rules.windows_auth import RULES as WINDOWS_AUTH_RULES
from detection.rules.windows_iam import RULES as WINDOWS_IAM_RULES

# List of rules to process
# TODO Add more rules to this section.
RULES = (
    LINUX_AUTH_RULES
    + WINDOWS_AUTH_RULES
    + WINDOWS_IAM_RULES
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
    # TODO Atomic rules need to be loaded via YAML files.
    for rule in RULES:
        finding = rule(event)
        if finding is not None:
            findings.append(finding)

    return findings