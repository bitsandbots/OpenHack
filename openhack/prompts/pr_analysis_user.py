"""
User prompt template for PR diff security analysis.
"""

PR_ANALYSIS_USER_TEMPLATE = """{context_section}Analyze the following git diff for security vulnerabilities:

```diff
{pr_diff}
```

Respond with a JSON array of findings only:"""
