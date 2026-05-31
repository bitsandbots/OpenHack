"""
Django data exposure detection prompt.
"""

DJANGO_DATA_EXPOSURE_PROMPT = """## Data Exposure in Django

### What to Look For

1. **DRF serializers exposing sensitive fields**
2. **DEBUG=True in production**
3. **Verbose error pages leaking internals**
4. **Model __str__ or __repr__ leaking sensitive data in logs**

### Django-Specific Patterns

**Serializer Over-Exposure (Vulnerable)**:
```python
# VULNERABLE: Exposes ALL fields including password hash
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # Includes password, is_superuser, etc.

# VULNERABLE: Missing exclude for sensitive fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'is_staff']

# SAFE: Explicit safe fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
```

**Debug Mode (Vulnerable)**:
```python
# settings.py -- VULNERABLE in production
DEBUG = True  # Exposes full stack traces, SQL queries, settings

# Also check for environment-conditional debug that might be misconfigured:
DEBUG = os.environ.get('DEBUG', True)  # Defaults to True!
```

**Values/Values_list Leaking**:
```python
# VULNERABLE: Returning raw queryset data with sensitive fields
def api_users(request):
    users = User.objects.values()  # Includes password hash!
    return JsonResponse(list(users), safe=False)
```

### Search Patterns

1. `grep` for: `fields = '__all__'`, `fields = \\[` in serializers
2. `grep` for: `DEBUG = True`, `DEBUG = ` in settings files
3. `grep` for: `\\.values\\(\\)`, `\\.values_list\\(\\)` -- check for sensitive fields
4. `grep` for: `JsonResponse` and `json\\.dumps` with model data

### Severity Assessment

- **Critical**: Password hashes, tokens, or secrets exposed via API
- **High**: PII (email, phone, address) exposed to unauthorized users
- **Medium**: DEBUG=True in production (stack traces, SQL)
- **Low**: Non-sensitive internal data leakage
"""
