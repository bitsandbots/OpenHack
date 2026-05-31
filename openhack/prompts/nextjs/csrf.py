"""
Next.js CSRF (Cross-Site Request Forgery) detection prompt.
"""

NEXTJS_CSRF_PROMPT = """## CSRF (Cross-Site Request Forgery) Detection in Next.js

### What to Look For

1. **State-changing operations without CSRF tokens**
2. **Server Actions without proper validation**
3. **API routes accepting mutations without origin checks**

### Next.js Specific Patterns

**Server Actions (Next.js 14+)**:
Server Actions have built-in CSRF protection via the `next-action` header, BUT:

```typescript
'use server'
// POTENTIALLY VULNERABLE: If called via direct POST without header check
async function deleteAccount() {
  const session = await getSession();
  await db.user.delete({ where: { id: session.userId } });
}
```

**API Routes (Vulnerable)**:
```typescript
// pages/api/user/delete.ts
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  
  // VULNERABLE: No CSRF token validation
  const session = await getSession(req);
  await db.user.delete({ where: { id: session.userId } });
  res.json({ success: true });
}
```

**Route Handlers (App Router)**:
```typescript
// app/api/transfer/route.ts
export async function POST(req: Request) {
  // VULNERABLE: No origin/referer check, no CSRF token
  const { to, amount } = await req.json();
  await transferMoney(to, amount);
  return Response.json({ success: true });
}
```

### Protection Checks

1. Look for CSRF token validation in forms/API calls
2. Check for `SameSite` cookie attributes
3. Verify origin/referer header checks on sensitive endpoints
4. Check if using libraries like `csrf` or `next-auth` (which handles CSRF)

### Search Patterns

1. `grep` for: state-changing operations (delete, update, create, transfer)
2. Check if they validate CSRF tokens
3. Look for `SameSite` in cookie configuration
4. Check `next-auth` config for CSRF settings

### Severity Assessment

- **Critical**: Financial transactions, account deletion without CSRF
- **High**: Data modification affecting user security
- **Medium**: Non-sensitive data modification
- **Low**: Actions with limited impact
"""
