"""
Flask injection vulnerabilities detection prompt.
"""

FLASK_INJECTION_PROMPT = """## Injection Vulnerabilities in Flask

### What to Look For

1. **SQL injection via SQLAlchemy raw queries**
2. **Jinja2 Server-Side Template Injection (SSTI)**
3. **Command injection via subprocess/os**
4. **eval/exec with request data**

### Flask-Specific Patterns

**SQLAlchemy Injection (Vulnerable)**:
```python
# VULNERABLE: text() with f-string
from sqlalchemy import text
result = db.session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# VULNERABLE: db.engine.execute with format string
db.engine.execute("SELECT * FROM users WHERE id = %s" % user_id)

# VULNERABLE: filter with string interpolation
User.query.filter(f"name = '{request.args['name']}'")

# SAFE: Parameterized
result = db.session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
```

**Jinja2 SSTI (Vulnerable)**:
```python
# VULNERABLE: render_template_string with user input
from flask import render_template_string
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string(f'Hello {{name}}!')  # SSTI!
    # Attack: ?name={{config.SECRET_KEY}} or {{''.__class__.__mro__[1].__subclasses__()}}

# SAFE: Use render_template with separate template file
return render_template('greet.html', name=name)
```

**Command Injection (Vulnerable)**:
```python
# VULNERABLE: shell=True with user input
import subprocess
subprocess.call(f"ping {request.form['host']}", shell=True)
os.system(f"nslookup {request.args['domain']}")

# SAFE: Argument list
subprocess.call(["ping", "-c", "1", request.form['host']])
```

**Eval/Exec (Vulnerable)**:
```python
# VULNERABLE: eval with request data
result = eval(request.form['expression'])
exec(request.json['code'])
```

### Search Patterns

1. `grep` for: `db\\.session\\.execute`, `db\\.engine\\.execute`, `text\\(`
2. `grep` for: `render_template_string` -- almost always dangerous
3. `grep` for: `subprocess`, `os\\.system`, `os\\.popen`, `shell=True`
4. `grep` for: `eval\\(`, `exec\\(`, `compile\\(`

### Severity Assessment

- **Critical**: SQL injection allowing data extraction
- **Critical**: SSTI (leads to RCE via Jinja2 sandbox escape)
- **Critical**: Command injection
- **High**: eval/exec with partially controlled input
"""
