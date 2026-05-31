"""
Flask data exposure detection prompt.
"""

FLASK_DATA_EXPOSURE_PROMPT = """## Data Exposure in Flask

### What to Look For

1. **jsonify(model.__dict__) leaking internal fields**
2. **Marshmallow schemas exposing sensitive fields**
3. **DEBUG=True with Werkzeug debugger (RCE!)**
4. **Hardcoded app.secret_key**

### Flask-Specific Patterns

**Model Dump (Vulnerable)**:
```python
# VULNERABLE: Dumping full model including password hash
@app.route('/api/users/<int:uid>')
def get_user(uid):
    user = User.query.get_or_404(uid)
    return jsonify(user.__dict__)  # Includes _sa_instance_state, password_hash!

# VULNERABLE: vars() or to_dict() without filtering
return jsonify(vars(user))
return jsonify({c.name: getattr(user, c.name) for c in user.__table__.columns})
```

**Marshmallow Over-Exposure (Vulnerable)**:
```python
# VULNERABLE: Includes sensitive fields
class UserSchema(Schema):
    class Meta:
        fields = ('id', 'username', 'email', 'password_hash', 'is_admin', 'api_key')

# SAFE: Exclude sensitive fields
class UserSchema(Schema):
    class Meta:
        fields = ('id', 'username', 'email')
```

**Werkzeug Debugger (Critical)**:
```python
# VULNERABLE: DEBUG=True in production = Remote Code Execution!
app.run(debug=True, host='0.0.0.0')
# The Werkzeug debugger allows arbitrary Python execution in the browser
# via the interactive console at /__debugger__

# Also check:
app.config['DEBUG'] = True
FLASK_DEBUG=1  # in .env or environment
```

**Secret Key Exposure (Vulnerable)**:
```python
# VULNERABLE: Hardcoded secret (session forgery)
app.secret_key = 'my-secret-key'
app.config['SECRET_KEY'] = 'dev-secret'

# VULNERABLE: Weak fallback
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-insecure')
```

### Search Patterns

1. `grep` for: `jsonify\\(.*__dict__`, `jsonify\\(vars\\(`, `to_dict\\(`
2. `grep` for: `debug=True`, `DEBUG = True`, `FLASK_DEBUG`
3. `grep` for: `secret_key =`, `SECRET_KEY`
4. `grep` for: `class.*Schema` -- check Meta.fields for sensitive columns

### Severity Assessment

- **Critical**: DEBUG=True in production (Werkzeug debugger = RCE)
- **Critical**: Password hashes or API keys in API responses
- **High**: Hardcoded SECRET_KEY (session forgery)
- **High**: PII exposed to unauthorized users
- **Medium**: Non-sensitive internal data leakage
"""
