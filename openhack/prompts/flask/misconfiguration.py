"""
Flask security misconfiguration detection prompt.
"""

FLASK_MISCONFIGURATION_PROMPT = """## Security Misconfiguration in Flask

### What to Look For

1. **app.secret_key hardcoded or weak**
2. **DEBUG=True in production (Werkzeug debugger = RCE)**
3. **Missing session cookie security flags**
4. **Overly permissive CORS**

### Flask-Specific Patterns

**Secret Key (Vulnerable)**:
```python
# VULNERABLE: Hardcoded secret key
app.secret_key = 'super-secret-key-123'
app.config['SECRET_KEY'] = 'development'

# VULNERABLE: Predictable or short secret
app.secret_key = 'secret'

# VULNERABLE: Weak fallback default
app.secret_key = os.environ.get('SECRET_KEY', 'default-key')
```

**Cookie Security (Vulnerable)**:
```python
# VULNERABLE: Missing security flags
app.config['SESSION_COOKIE_SECURE'] = False     # Sent over HTTP
app.config['SESSION_COOKIE_HTTPONLY'] = False    # JS accessible
app.config['SESSION_COOKIE_SAMESITE'] = None    # Cross-site allowed
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)  # 1 year sessions!
```

**CORS Misconfiguration (Vulnerable)**:
```python
# VULNERABLE: Allow all origins
from flask_cors import CORS
CORS(app)  # Default allows all origins

# VULNERABLE: Wildcard with credentials
CORS(app, origins='*', supports_credentials=True)

# SAFE: Specific origins
CORS(app, origins=['https://app.example.com'], supports_credentials=True)
```

**Host Header (Vulnerable)**:
```python
# VULNERABLE: Running on 0.0.0.0 without SERVER_NAME
app.run(host='0.0.0.0', port=5000)
# No SERVER_NAME set -- accepts any Host header
```

### Search Patterns

1. `grep` for: `secret_key`, `SECRET_KEY` in app config
2. `grep` for: `debug=True`, `DEBUG = True`, `FLASK_DEBUG`
3. `grep` for: `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`
4. `grep` for: `CORS\\(`, `flask_cors`
5. `grep` for: `app\\.run\\(` -- check for debug and host params

### Severity Assessment

- **Critical**: DEBUG=True on public host (Werkzeug debugger = RCE)
- **High**: Hardcoded or weak SECRET_KEY (session forgery, cookie tampering)
- **Medium**: Missing cookie security flags
- **Medium**: CORS allowing all origins with credentials
- **Low**: Missing HTTPS enforcement headers
"""
