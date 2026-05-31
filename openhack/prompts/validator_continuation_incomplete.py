"""
Continuation prompt for the Validator agent when validation is incomplete.

Use .format(total_validated=..., total_findings=..., unvalidated_count=...) to fill in the dynamic values.
"""

VALIDATOR_CONTINUATION_INCOMPLETE = (
    "You stopped early. You've only validated {total_validated} of {total_findings} findings. "
    "There are still {unvalidated_count} findings that need validation. "
    "Please continue validating the remaining findings using validate_finding for each one, "
    "then call finish_validation when complete."
)
