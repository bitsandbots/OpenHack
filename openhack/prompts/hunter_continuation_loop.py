"""
Continuation prompt for the Hunter agent when it is stuck in a tool call loop.

Use .format(tool_name=...) to fill in the repeated tool name.
"""

HUNTER_CONTINUATION_LOOP = (
    "You've been calling {tool_name} repeatedly without making progress. "
    "Stop listing directories and start reading actual source code files. "
    "Use read_file to examine route handlers, API endpoints, and authentication code. "
    "Look for vulnerabilities in the code and report them using report_finding."
)
