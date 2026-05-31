"""
Continuation prompt for the Hunter agent when no findings after many iterations.

Use .format(files_count=..., iteration=...) to fill in the dynamic values.
"""

HUNTER_CONTINUATION_NO_PROGRESS = (
    "You've read {files_count} files over {iteration} iterations with zero findings. "
    "This is unusual — most codebases have at least some security issues. "
    "You MUST now either call report_finding or finish_hunt.\n\n"
    "Re-examine with these specific checks:\n"
    "1. IDOR: Any ViewSet/APIView that fetches objects by pk/id from URL without "
    "checking request.user ownership — even if authentication is required\n"
    "2. Mass assignment: Serializers using fields='__all__' or missing read_only on "
    "privileged fields (is_staff, role, organization_id)\n"
    "3. SQL injection: .raw(), .extra(), RawSQL, cursor.execute() with f-strings or .format()\n"
    "4. SSRF: User-controlled URLs in requests.get/post, webhook URLs, callback URLs\n"
    "5. Auth gaps: Endpoints with weaker permission_classes than similar endpoints\n"
    "6. Information disclosure: Verbose error responses, stack traces, internal IDs in responses\n\n"
    "Report at confidence='medium' for uncertain findings — a validator will verify. "
    "Under-reporting is a critical failure mode for a security scanner."
)
