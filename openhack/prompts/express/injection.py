"""
Express.js injection vulnerabilities detection prompt.
"""

EXPRESS_INJECTION_PROMPT = """## Injection Vulnerabilities in Express.js

### What to Look For

1. **SQL injection via raw queries or string concatenation**
2. **NoSQL injection via MongoDB operator injection**
3. **Command injection via child_process**
4. **eval / new Function with user input**

### Express-Specific Patterns

**SQL Injection (Vulnerable)**:
```javascript
// VULNERABLE: String concatenation in queries
app.get('/users', (req, res) => {
  const query = `SELECT * FROM users WHERE name = '${req.query.name}'`;
  pool.query(query);  // SQL injection!
});

// VULNERABLE: Sequelize literal / raw
const users = await User.findAll({
  where: sequelize.literal(`name = '${req.body.name}'`),
});
const result = await sequelize.query(`SELECT * FROM t WHERE id = ${req.params.id}`);

// VULNERABLE: Knex raw
const rows = await knex.raw(`SELECT * FROM users WHERE id = ${req.params.id}`);

// SAFE: Parameterized
pool.query('SELECT * FROM users WHERE name = $1', [req.query.name]);
```

**NoSQL Injection (Vulnerable)**:
```javascript
// VULNERABLE: MongoDB operator injection
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    email: req.body.email,
    password: req.body.password,  // { "$ne": "" } bypasses auth!
  });
});

// SAFE: Coerce to string
const email = String(req.body.email);
```

**Command Injection (Vulnerable)**:
```javascript
// VULNERABLE: exec with user input
const { exec } = require('child_process');
exec(`convert ${req.body.filename} output.png`);

// SAFE: execFile with args array
const { execFile } = require('child_process');
execFile('convert', [req.body.filename, 'output.png']);
```

### Search Patterns

1. `grep` for: `pool\\.query\\(`, `\\.query\\(.*\\$\\{`, `sequelize\\.query`
2. `grep` for: `\\.findOne\\(`, `\\.find\\(` -- check for untyped body params
3. `grep` for: `exec\\(`, `execSync\\(`, `spawn\\(` with template literals
4. `grep` for: `eval\\(`, `new Function\\(`, `vm\\.runIn`

### Severity Assessment

- **Critical**: SQL injection allowing data extraction or modification
- **Critical**: Command injection allowing code execution
- **High**: NoSQL injection with authentication bypass
- **Medium**: Limited injection with restricted impact
"""
