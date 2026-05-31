"""
Next.js XSS (Cross-Site Scripting) detection prompt.
"""

NEXTJS_XSS_PROMPT = """## XSS (Cross-Site Scripting) Detection in Next.js

### What to Look For

1. **dangerouslySetInnerHTML with user input**
2. **Unescaped rendering in non-React contexts**
3. **DOM manipulation with user data**
4. **URL-based XSS via searchParams/query**

### Next.js Specific Patterns

**React (Usually Safe)**:
React auto-escapes by default, but watch for:

```tsx
// VULNERABLE: dangerouslySetInnerHTML with user content
function Comment({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// VULNERABLE: User input in href without validation
function Link({ url }) {
  return <a href={url}>Click</a>; // javascript: URLs are XSS
}

// VULNERABLE: User input in event handlers
function Button({ onClick }) {
  return <button onClick={() => eval(onClick)}>Click</button>;
}
```

**Server Components (App Router)**:
```tsx
// Less XSS risk but watch for:
async function Page({ searchParams }) {
  // If this HTML is rendered unsafely downstream
  const userHtml = searchParams.content;
  return <RenderMarkdown content={userHtml} />; // Depends on RenderMarkdown implementation
}
```

**API Routes returning HTML**:
```typescript
// pages/api/preview.ts
export default function handler(req, res) {
  // VULNERABLE: Reflecting user input as HTML
  res.setHeader('Content-Type', 'text/html');
  res.send(`<html><body>${req.query.content}</body></html>`);
}
```

### Search Patterns

1. `grep` for: `dangerouslySetInnerHTML`, `innerHTML`, `__html`
2. `grep` for: `document\\.write`, `eval\\(`, `new Function\\(`
3. Look for user input flowing to these sinks
4. Check markdown/rich text renderers for sanitization

### Severity Assessment

- **Critical**: Stored XSS affecting all users
- **High**: Reflected XSS requiring social engineering
- **Medium**: Self-XSS or limited scope
- **Low**: XSS with significant barriers to exploitation
"""
