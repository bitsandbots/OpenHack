"""
Express.js SSRF detection prompt.
"""

EXPRESS_SSRF_PROMPT = """## SSRF (Server-Side Request Forgery) in Express.js

### What to Look For

1. **User-controlled URLs passed to HTTP clients (axios, fetch, got, undici)**
2. **Webhook/callback URL injection**
3. **URL fetching in proxy or preview features**
4. **Image/file download from user-provided URLs**

### Express-Specific Patterns

**Axios / node-fetch (Vulnerable)**:
```javascript
// VULNERABLE: User-controlled URL
app.post('/api/fetch-preview', async (req, res) => {
  const response = await axios.get(req.body.url);  // SSRF!
  res.json({ title: parseTitle(response.data) });
});

// VULNERABLE: fetch with user URL
const data = await fetch(req.query.url);

// VULNERABLE: got / undici
const response = await got(req.body.webhook_url);
```

**Proxy Pattern (Vulnerable)**:
```javascript
// VULNERABLE: Proxying requests to user-specified hosts
app.all('/proxy/*', async (req, res) => {
  const target = req.params[0];  // User controls destination
  const response = await axios.get(`http://${target}`);
  res.send(response.data);
});
```

**Webhook Registration (Vulnerable)**:
```javascript
// VULNERABLE: Storing and later calling user-provided URLs
app.post('/api/webhooks', auth, async (req, res) => {
  await Webhook.create({ url: req.body.url, userId: req.user.id });
  // Later: axios.post(webhook.url, eventPayload) -- hits internal services
});
```

### Search Patterns

1. `grep` for: `axios\\.get\\(`, `axios\\.post\\(`, `axios\\(`
2. `grep` for: `fetch\\(`, `got\\(`, `undici`
3. `grep` for: `http\\.request\\(`, `https\\.request\\(`
4. Trace URL argument -- does it come from `req.body`, `req.query`, `req.params`?

### Severity Assessment

- **High**: SSRF reaching cloud metadata (169.254.169.254) or internal services
- **High**: SSRF with response body returned to attacker
- **Medium**: Blind SSRF (request sent, no response returned)
- **Low**: SSRF limited to specific protocols or hosts by validation
"""
