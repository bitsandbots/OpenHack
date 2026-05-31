"""
Django CSRF detection prompt.
"""

DJANGO_CSRF_PROMPT = """## CSRF (Cross-Site Request Forgery) Detection in Django

### What to Look For

1. **@csrf_exempt on state-changing views**
2. **CsrfViewMiddleware removed from MIDDLEWARE**
3. **DRF SessionAuthentication without CSRF enforcement**

### Django-Specific Patterns

**Decorator Bypass (Vulnerable)**:
```python
# VULNERABLE: CSRF disabled on state-changing endpoint
@csrf_exempt
def transfer_money(request):
    if request.method == 'POST':
        amount = request.POST['amount']
        to_user = request.POST['to']
        transfer(request.user, to_user, amount)
        return JsonResponse({"ok": True})
```

**Middleware Removal (Vulnerable)**:
```python
# settings.py -- VULNERABLE: CSRF middleware removed entirely
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',  # REMOVED!
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]
```

**DRF Session Auth (Vulnerable)**:
```python
# VULNERABLE: SessionAuthentication used but CSRF not enforced
# when combined with custom exception handler that swallows 403s
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
}
```

### Search Patterns

1. `grep` for: `@csrf_exempt`, `csrf_exempt`
2. Check `settings.py` MIDDLEWARE list for `CsrfViewMiddleware`
3. `grep` for: `SessionAuthentication` in DRF settings
4. Look for views that accept POST/PUT/DELETE without `{% csrf_token %}` in templates

### Severity Assessment

- **Critical**: Financial transactions or account operations without CSRF
- **High**: Data modification affecting user security
- **Medium**: Non-sensitive data modification
- **Low**: Actions with limited impact
"""
