"""
Express.js IDOR (Insecure Direct Object Reference) detection prompt.
"""

EXPRESS_IDOR_PROMPT = """## IDOR (Insecure Direct Object Reference) Detection in Express.js

### What to Look For

1. **req.params.id used directly in DB queries without ownership check**
2. **Missing user scoping in Mongoose/Sequelize/Prisma queries**
3. **Enumerable IDs (sequential integers)**

### Express-Specific Patterns

**Mongoose (Vulnerable)**:
```javascript
// VULNERABLE: No ownership check
app.get('/api/documents/:id', async (req, res) => {
  const doc = await Document.findById(req.params.id);
  res.json(doc);  // Any user can access any document
});

// SAFE: Scoped to user
app.get('/api/documents/:id', auth, async (req, res) => {
  const doc = await Document.findOne({ _id: req.params.id, owner: req.user.id });
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json(doc);
});
```

**Prisma (Vulnerable)**:
```javascript
// VULNERABLE: Direct ID lookup without ownership
app.get('/api/orders/:id', async (req, res) => {
  const order = await prisma.order.findUnique({
    where: { id: req.params.id },  // No userId filter!
  });
  res.json(order);
});
```

**Sequelize (Vulnerable)**:
```javascript
// VULNERABLE: No user scoping
app.put('/api/posts/:id', auth, async (req, res) => {
  const post = await Post.findByPk(req.params.id);
  await post.update(req.body);  // Any user can update any post!
});

// SAFE: Scoped query
const post = await Post.findOne({
  where: { id: req.params.id, userId: req.user.id }
});
```

### Search Patterns

1. `grep` for: `findById\\(req\\.params`, `findByPk\\(req\\.params`
2. `grep` for: `findUnique.*req\\.params`, `findOne.*req\\.params`
3. Check if queries include `userId`, `ownerId`, or `req.user` scoping
4. Look for `req.params.id` flowing to any DB query without ownership check

### Severity Assessment

- **Critical**: Access to other users' sensitive data (PII, financial)
- **High**: Modification of other users' resources
- **Medium**: Read access to non-sensitive resources
- **Low**: Informational leaks with no security impact
"""
