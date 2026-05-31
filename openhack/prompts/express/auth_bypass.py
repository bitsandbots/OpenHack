"""
Express.js authentication/authorization bypass detection prompt.
"""

EXPRESS_AUTH_BYPASS_PROMPT = """## Authentication/Authorization Bypass in Express.js

### What to Look For

1. **Routes missing auth middleware**
2. **Passport.js misconfiguration**
3. **JWT vulnerabilities (none algorithm, weak secret)**
4. **Broken middleware ordering**

### Express-Specific Patterns

**Missing Middleware (Vulnerable)**:
```javascript
// VULNERABLE: No auth middleware on sensitive route
app.delete('/api/users/:id', async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ deleted: true });
});

// SAFE: Auth middleware applied
app.delete('/api/users/:id', authenticate, authorize('admin'), async (req, res) => {
  ...
});
```

**Route Group Gaps (Vulnerable)**:
```javascript
// VULNERABLE: Auth applied to router but some routes added before
app.get('/api/admin/stats', getStats);       // No auth!
app.use('/api/admin', authMiddleware);        // Auth applied AFTER
app.get('/api/admin/users', getAdminUsers);   // Protected
```

**JWT Vulnerabilities (Vulnerable)**:
```javascript
// VULNERABLE: No algorithm restriction
const decoded = jwt.verify(token, secret);  // Accepts 'none' algorithm!

// VULNERABLE: Weak/hardcoded secret
const token = jwt.sign(payload, 'secret123');

// SAFE: Algorithm whitelist
const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

**Passport.js Gaps (Vulnerable)**:
```javascript
// VULNERABLE: isAuthenticated() check missing
app.get('/profile', (req, res) => {
  res.json(req.user);  // req.user may be undefined
});
```

### Search Patterns

1. `grep` for: `app\\.get\\(`, `app\\.post\\(`, `router\\.get\\(` -- check for auth middleware
2. `grep` for: `jwt\\.verify`, `jwt\\.sign` -- check algorithm and secret
3. `grep` for: `passport\\.authenticate`, `isAuthenticated`
4. Check middleware ordering in main app file

### Severity Assessment

- **Critical**: Admin endpoints accessible without auth
- **High**: User data modification without auth
- **Medium**: Auth bypass with limited scope
- **Low**: Informational endpoints exposed
"""
