"""
Flask authentication/authorization bypass detection prompt.
"""

FLASK_AUTH_BYPASS_PROMPT = """## Authentication/Authorization Bypass in Flask

### What to Look For

1. **Missing @login_required decorators**
2. **Broken Flask-Login is_authenticated checks**
3. **Unprotected Blueprint routes**
4. **Flask-Admin without auth**

### Flask-Specific Patterns

**Missing Decorator (Vulnerable)**:
```python
# VULNERABLE: No auth on sensitive endpoint
@app.route('/admin/users', methods=['GET', 'DELETE'])
def manage_users():
    if request.method == 'DELETE':
        User.query.filter_by(id=request.form['id']).delete()
        db.session.commit()
    return jsonify([u.to_dict() for u in User.query.all()])

# SAFE: Auth required
@app.route('/admin/users')
@login_required
def manage_users():
    ...
```

**Blueprint Without Auth (Vulnerable)**:
```python
# VULNERABLE: Entire blueprint has no auth
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/settings')
def admin_settings():
    return jsonify(get_all_settings())  # Exposed!

# SAFE: before_request hook for entire blueprint
@admin_bp.before_request
@login_required
def admin_auth():
    if not current_user.is_admin:
        abort(403)
```

**Flask-Admin Exposure (Vulnerable)**:
```python
# VULNERABLE: Flask-Admin with no auth
from flask_admin import Admin
admin = Admin(app)
admin.add_view(ModelView(User, db.session))  # Anyone can CRUD users!

# SAFE: Custom ModelView with auth
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
```

**JWT Misconfiguration (Vulnerable)**:
```python
# VULNERABLE: No algorithm restriction
import jwt
decoded = jwt.decode(token, secret, algorithms=None)  # Accepts 'none'!

# VULNERABLE: Weak/hardcoded secret
app.config['JWT_SECRET_KEY'] = 'super-secret'
```

### Search Patterns

1. `grep` for: `@app\\.route`, `@.*\\.route` -- check for `@login_required`
2. `grep` for: `Blueprint\\(` -- check if before_request has auth
3. `grep` for: `Flask-Admin`, `ModelView` -- check for `is_accessible`
4. `grep` for: `jwt\\.decode`, `JWT_SECRET_KEY`

### Severity Assessment

- **Critical**: Admin panels or management endpoints without auth
- **High**: User data modification without auth
- **Medium**: Read access to non-sensitive data
- **Low**: Informational endpoints exposed
"""
