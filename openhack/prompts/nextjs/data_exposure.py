"""
Next.js sensitive data exposure detection prompt.
"""

NEXTJS_DATA_EXPOSURE_PROMPT = """## Sensitive Data Exposure in Next.js

### What to Look For

1. **Secrets in client bundles**
2. **Sensitive data in server component props**
3. **Verbose error messages**
4. **Exposed environment variables**

### Client Bundle Leaks

**Exposed Env Variables**:
```typescript
// VULNERABLE: NEXT_PUBLIC_ exposes to client
// .env
NEXT_PUBLIC_API_KEY=secret123  // Exposed in browser!
DATABASE_URL=...               // Safe, server only

// next.config.js
module.exports = {
  env: {
    SECRET_KEY: process.env.SECRET_KEY, // EXPOSED to client!
  },
};
```

**Server-to-Client Data Leak**:
```tsx
// VULNERABLE: Server component passing sensitive data to client
async function Page() {
  const user = await db.user.findUnique({
    where: { id: session.userId },
    include: { password: true } // Oops!
  });
  return <ClientComponent user={user} />; // Password sent to client!
}
```

### API Response Leaks

```typescript
// VULNERABLE: Returning full user object
export async function GET() {
  const users = await db.user.findMany();
  return Response.json(users); // Includes passwords, tokens, etc!
}

// SAFE: Select specific fields
export async function GET() {
  const users = await db.user.findMany({
    select: { id: true, name: true, email: true }
  });
  return Response.json(users);
}
```

### Error Information Leaks

```typescript
// VULNERABLE: Exposing stack traces
export async function GET() {
  try {
    // ...
  } catch (error) {
    return Response.json({ error: error.stack }); // Stack trace exposed!
  }
}
```

### Search Patterns

1. `grep` for: `NEXT_PUBLIC_` env vars (check what's exposed)
2. Check `next.config.js` for `env` configuration
3. `grep` for: `.env` file reads
4. Look for full model objects passed to client components
5. Check error handlers for verbose messages

### Severity Assessment

- **Critical**: API keys, database credentials exposed
- **High**: User passwords, tokens, PII exposed
- **Medium**: Internal paths, versions exposed
- **Low**: Non-sensitive debug information
"""
