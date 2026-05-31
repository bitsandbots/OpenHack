"""
Django injection vulnerabilities detection prompt.
"""

DJANGO_INJECTION_PROMPT = """## Injection Vulnerabilities in Django

### What to Look For

1. **SQL injection via ORM escape hatches**
2. **Command injection via subprocess/os**
3. **Template injection via mark_safe / |safe**
4. **LDAP / NoSQL injection in custom backends**

### Django-Specific Patterns

**ORM Escape Hatches (Vulnerable)**:
```python
# VULNERABLE: raw() with string formatting
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
User.objects.raw("SELECT * FROM users WHERE name = '%s'" % name)

# VULNERABLE: extra() with user input
queryset.extra(where=[f"name = '{user_input}'"])

# VULNERABLE: RawSQL expression
from django.db.models.expressions import RawSQL
queryset.annotate(val=RawSQL(f"SELECT col FROM t WHERE id = {uid}", []))

# SAFE: Parameterized
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
```

**Command Injection**:
```python
# VULNERABLE: shell=True with user input
import subprocess
subprocess.call(f"convert {filename} output.png", shell=True)
os.system(f"grep {query} /var/log/app.log")

# SAFE: argument list
subprocess.call(["convert", filename, "output.png"])
```

**Template Injection**:
```python
# VULNERABLE: mark_safe with user content
from django.utils.safestring import mark_safe
return mark_safe(f"<div>{user_input}</div>")

# VULNERABLE: |safe filter in templates on user data
# {{ user_bio|safe }}
```

### Search Patterns

1. `grep` for: `\\.raw\\(`, `\\.extra\\(`, `RawSQL`, `\\.execute\\(`
2. `grep` for: `subprocess`, `os\\.system`, `os\\.popen`, `shell=True`
3. `grep` for: `mark_safe`, `\\|safe`, `format_html` used incorrectly
4. Look for string formatting (`f"`, `%`, `.format(`) near query calls

### Severity Assessment

- **Critical**: SQL injection allowing data extraction or modification
- **Critical**: Command injection allowing code execution
- **High**: Template injection leading to XSS
- **Medium**: Limited injection with restricted impact
"""
