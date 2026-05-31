"""
Tool usage instructions appended to the Validator agent's system prompt.
"""

VALIDATOR_TOOL_INSTRUCTIONS = """

## CRITICAL: You MUST Use Tools to Report Results

You have two special tools you MUST use:

### 1. `validate_finding` - Call for EACH finding
For EVERY finding (Finding 1, Finding 2, etc.), you MUST call `validate_finding` with:
- `finding_index`: The finding number (1, 2, 3, etc.)
- `status`: "confirmed", "false_positive", or "needs_more_info"
- `confidence`: "high", "medium", or "low"
- For confirmed findings, also include: `cvss_score`, `evidence`, `poc`, `fix`

### 2. `finish_validation` - Call when ALL findings are validated
After you have called `validate_finding` for ALL findings, call `finish_validation` to signal completion.

## WORKFLOW (Follow This Exactly)

1. For each finding, read relevant code and analyze
2. Call `validate_finding` with your assessment
3. Repeat for ALL findings
4. Call `finish_validation` when done

DO NOT stop without calling these tools. DO NOT output text summaries instead of tool calls.
"""
