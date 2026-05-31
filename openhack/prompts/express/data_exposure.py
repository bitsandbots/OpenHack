"""
Express.js data exposure detection prompt.
"""

EXPRESS_DATA_EXPOSURE_PROMPT = """## Data Exposure in Express.js

### What to Look For

1. **Returning full model objects including password hashes**
2. **Verbose error middleware exposing stack traces**
3. **Missing field selection on database queries**
4. **Environment variables or secrets in responses**

### Express-Specific Patterns

**Full Model Leak (Vulnerable)**:
```javascript
// VULNERABLE: Returns entire user object including password hash
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);  // Includes password, tokens, internal fields!
});

// SAFE: Select only needed fields (Mongoose)
const user = await User.findById(req.params.id).select('-password -__v');

// SAFE: Pick fields explicitly
const { id, name, email } = await User.findById(req.params.id);
res.json({ id, name, email });
```

**Error Middleware Leak (Vulnerable)**:
```javascript
// VULNERABLE: Stack traces in production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,       // Full stack trace!
    query: err.sql,         // SQL query that failed!
  });
});
```

**Sequelize/Prisma Over-fetching (Vulnerable)**:
```javascript
// VULNERABLE: Returns all columns
const users = await prisma.user.findMany();  // Includes password hash!
res.json(users);

// SAFE: Select specific fields
const users = await prisma.user.findMany({
  select: { id: true, name: true, email: true },
});
```

**Env Vars in Response (Vulnerable)**:
```javascript
// VULNERABLE: Leaking config/secrets
app.get('/api/config', (req, res) => {
  res.json(process.env);  // ALL env vars including secrets!
});
```

### Search Patterns

1. `grep` for: `res\\.json\\(` with model variable -- check if sensitive fields excluded
2. `grep` for: `err\\.stack`, `err\\.sql` in error handlers
3. `grep` for: `\\.select\\('-password` -- verify password exclusion exists
4. `grep` for: `process\\.env` in API responses

### Severity Assessment

- **Critical**: Password hashes, API keys, or secrets in API responses
- **High**: PII (email, phone, address) exposed to unauthorized users
- **Medium**: Stack traces or SQL queries in error responses
- **Low**: Non-sensitive internal data leakage
"""
