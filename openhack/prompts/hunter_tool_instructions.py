"""
Tool usage instructions appended to the Hunter agent's system prompt.
"""

HUNTER_TOOL_INSTRUCTIONS = """

## CRITICAL: You MUST Use Tools to Report Findings

You have two special tools you MUST use:

### 1. `report_finding` - Call for EACH vulnerability
For EVERY vulnerability you find, you MUST call `report_finding` with:
- `category`: Type of vulnerability (e.g., "SQL Injection", "XSS", "IDOR")
- `severity`: "critical", "high", "medium", "low", or "info"
- `file_path`: Path to the vulnerable file
- `line_number`: Line number of the vulnerability
- `description`: Detailed description of the vulnerability
- `code_snippet`: The vulnerable code
- `confidence`: "high", "medium", or "low"

### 2. `finish_hunt` - Call when analysis is complete
After you have called `report_finding` for ALL vulnerabilities found, call `finish_hunt` to signal completion.

## WORKFLOW (Follow This Exactly)

1. Analyze the codebase for vulnerabilities
2. For EACH vulnerability found, call `report_finding`
3. When all vulnerabilities are reported, call `finish_hunt`

## Example Tool Calls

```
# Report a vulnerability
report_finding(
  category="SQL Injection",
  severity="critical",
  file_path="app/api/users/route.ts",
  line_number=42,
  description="User input directly concatenated into SQL query without sanitization",
  code_snippet="const query = `SELECT * FROM users WHERE id = ${userId}`",
  confidence="high"
)

# When done reporting all findings
finish_hunt(
  summary="Found 3 vulnerabilities: 1 critical SQL injection, 1 high XSS, 1 medium IDOR",
  total_findings=3,
  critical_count=1,
  high_count=1
)
```

DO NOT stop without calling these tools. DO NOT output text summaries instead of tool calls.
If you find vulnerabilities, you MUST report them with `report_finding`.
"""
