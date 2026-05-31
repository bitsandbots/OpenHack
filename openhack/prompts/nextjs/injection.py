"""
Next.js injection vulnerabilities detection prompt.
"""

NEXTJS_INJECTION_PROMPT = """## Injection Vulnerabilities in Next.js

### SQL Injection

**Prisma (Usually Safe)**:
```typescript
// SAFE: Parameterized query
await prisma.user.findMany({ where: { email: userInput } });

// VULNERABLE: Raw query with interpolation
await prisma.$queryRaw`SELECT * FROM users WHERE email = '${userInput}'`;
await prisma.$executeRawUnsafe(`DELETE FROM users WHERE id = ${id}`);
```

**Raw Database Drivers**:
```typescript
// VULNERABLE: String concatenation
const result = await pool.query(`SELECT * FROM users WHERE id = '${userId}'`);

// SAFE: Parameterized
const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
```

### NoSQL Injection (MongoDB)

```typescript
// VULNERABLE: Object injection
const user = await User.findOne({ email: req.body.email, password: req.body.password });
// Attack: { "email": "admin@example.com", "password": { "$ne": "" } }

// SAFE: Type validation
const email = String(req.body.email);
const password = String(req.body.password);
```

### Command Injection

```typescript
// VULNERABLE
import { exec } from 'child_process';
exec(`convert ${userFilename} output.png`); // Command injection!

// SAFE: Use execFile with arguments array
import { execFile } from 'child_process';
execFile('convert', [userFilename, 'output.png']);
```

### Search Patterns

1. `grep` for: `\\$queryRaw`, `\\$executeRaw`, `query\\(.*\\$\\{`
2. `grep` for: `exec\\(`, `execSync\\(`, `spawn\\(`
3. `grep` for: `eval\\(`, `new Function\\(`
4. Look for string interpolation with user input in queries

### Severity Assessment

- **Critical**: SQL injection allowing data extraction or modification
- **Critical**: Command injection allowing code execution
- **High**: NoSQL injection with auth bypass
- **Medium**: Limited injection with restricted impact
"""
