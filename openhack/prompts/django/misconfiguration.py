"""
Django security misconfiguration detection prompt.
"""

DJANGO_MISCONFIGURATION_PROMPT = """## Security Misconfiguration in Django

### What to Look For

1. **Hardcoded SECRET_KEY**
2. **DEBUG=True in production**
3. **ALLOWED_HOSTS = ['*']**
4. **Insecure session/cookie settings**

### Django-Specific Patterns

**Secret Key Exposure (Vulnerable)**:
```python
# settings.py -- VULNERABLE: Hardcoded secret
SECRET_KEY = 'django-insecure-abc123def456...'

# VULNERABLE: Weak fallback
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-secret-key')
```

**Host Header Injection (Vulnerable)**:
```python
# VULNERABLE: Accepts any host
ALLOWED_HOSTS = ['*']

# VULNERABLE: Empty in production with DEBUG=False causes 400,
# but DEBUG=True + ALLOWED_HOSTS=[] accepts all
```

**Cookie/Session Settings (Vulnerable)**:
```python
# VULNERABLE: Missing security flags
SESSION_COOKIE_SECURE = False    # Sent over HTTP
SESSION_COOKIE_HTTPONLY = False   # Accessible via JavaScript
CSRF_COOKIE_SECURE = False       # CSRF token over HTTP
CSRF_COOKIE_HTTPONLY = False      # CSRF token in JS

# Missing HTTPS enforcement
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_PROXY_SSL_HEADER = None
```

**CORS Misconfiguration (django-cors-headers)**:
```python
# VULNERABLE: Allow all origins with credentials
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
```

### Search Patterns

1. `grep` for: `SECRET_KEY = ` in settings files
2. `grep` for: `ALLOWED_HOSTS`, `DEBUG = `
3. `grep` for: `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`
4. `grep` for: `CORS_ALLOW_ALL_ORIGINS`, `CORS_ALLOW_CREDENTIALS`
5. Check for `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`

### Severity Assessment

- **High**: Hardcoded SECRET_KEY (session forgery, RCE via pickle)
- **High**: DEBUG=True in production
- **Medium**: ALLOWED_HOSTS = ['*'] (host header injection)
- **Medium**: Missing cookie security flags
- **Low**: Missing HSTS or other hardening headers
"""
