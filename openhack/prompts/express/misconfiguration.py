"""
Express.js security misconfiguration detection prompt.
"""

EXPRESS_MISCONFIGURATION_PROMPT = """## Security Misconfiguration in Express.js

### What to Look For

1. **Overly permissive CORS configuration**
2. **Missing helmet security headers**
3. **express.static serving sensitive directories**
4. **Verbose X-Powered-By header**

### Express-Specific Patterns

**CORS Misconfiguration (Vulnerable)**:
```javascript
// VULNERABLE: Allow all origins with credentials
const cors = require('cors');
app.use(cors({ origin: true, credentials: true }));

// VULNERABLE: Wildcard origin
app.use(cors({ origin: '*' }));

// VULNERABLE: Reflecting Origin header without validation
app.use(cors({
  origin: (origin, callback) => callback(null, true),
  credentials: true,
}));

// SAFE: Allowlist
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
```

**Missing Helmet (Vulnerable)**:
```javascript
// VULNERABLE: No security headers
const app = express();
// Missing: app.use(helmet());
// No X-Content-Type-Options, no CSP, no HSTS, etc.
```

**Static File Exposure (Vulnerable)**:
```javascript
// VULNERABLE: Serving project root or sensitive dirs
app.use(express.static('.'));           // Exposes .env, package.json
app.use(express.static('..'));          // Parent directory!
app.use('/files', express.static('/'));  // Entire filesystem!
```

**Trust Proxy Misconfiguration**:
```javascript
// VULNERABLE: Trusting all proxies
app.set('trust proxy', true);  // Accepts any X-Forwarded-For
// Allows IP spoofing for rate limiters, geo-blocking, logging
```

### Search Patterns

1. `grep` for: `cors\\(`, `origin:` -- check CORS configuration
2. `grep` for: `helmet` -- verify it's actually used (not just installed)
3. `grep` for: `express\\.static` -- check what directories are served
4. `grep` for: `trust proxy`, `X-Powered-By`, `app\\.disable`

### Severity Assessment

- **High**: CORS allowing all origins with credentials
- **High**: express.static serving .env or project root
- **Medium**: Missing helmet / security headers
- **Medium**: Trust proxy misconfiguration
- **Low**: X-Powered-By header not disabled
"""
