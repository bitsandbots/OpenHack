"""
Continuation prompt for the Hunter agent when it stops without reporting findings.
"""

HUNTER_CONTINUATION_NO_FINDINGS = (
    "You stopped without reporting any vulnerabilities. You MUST now call report_finding "
    "or finish_hunt — do not respond with text only.\n\n"
    "Re-examine the code you've read. For each file, check:\n"
    "1. Does any user input reach a dangerous sink WITHOUT full validation? "
    "(ORM .raw()/.extra()/RawSQL, cursor.execute, subprocess, eval, template render, "
    "redirect, file open, HTTP request URL)\n"
    "2. Is there an authorization check that verifies the current user OWNS the object? "
    "Or does it only check 'is authenticated'? Missing ownership = IDOR.\n"
    "3. Can a user set fields they shouldn't via request.data? (mass assignment)\n"
    "4. Are there race conditions in non-atomic read-then-write patterns?\n\n"
    "Report findings at MEDIUM confidence if you're unsure — a downstream validator "
    "will confirm or reject. Under-reporting is worse than over-reporting.\n\n"
    "Call report_finding now for anything suspicious, then finish_hunt."
)
