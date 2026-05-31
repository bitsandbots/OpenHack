"""
Next.js authentication/authorization bypass detection prompt.
"""

NEXTJS_AUTH_BYPASS_PROMPT = """## Authentication/Authorization Bypass in Next.js

### What to Look For

1. **Missing middleware coverage**
2. **Inconsistent auth checks**
3. **JWT vulnerabilities**
4. **Session fixation/hijacking**

### Middleware Bypass (Next.js Specific)

**Incomplete Matcher**:
```typescript
// middleware.ts
export const config = {
  matcher: ['/dashboard/:path*', '/api/:path*']
  // VULNERABLE: /admin not protected!
};
```

**Path Traversal in Middleware**:
```typescript
// VULNERABLE: Path normalization issues
export function middleware(req) {
  if (req.nextUrl.pathname.startsWith('/api/admin')) {
    // Can be bypassed with /api/admin/../admin or /API/admin
  }
}
```

### Route-Level Auth Gaps

**App Router**:
```typescript
// app/admin/page.tsx
// VULNERABLE: No auth check in server component
export default async function AdminPage() {
  const users = await db.user.findMany(); // Anyone can access!
  return <UserList users={users} />;
}
```

**API Routes**:
```typescript
// VULNERABLE: Auth check missing
export async function DELETE(req) {
  const { id } = await req.json();
  await db.user.delete({ where: { id } }); // No auth check!
}
```

### Server Actions Auth

```typescript
'use server'
// VULNERABLE: No session validation
async function updateProfile(data: FormData) {
  const userId = data.get('userId'); // Trusting client-provided userId!
  await db.user.update({ where: { id: userId }, data: { ... } });
}
```

### Search Patterns

1. Review `middleware.ts` matcher patterns for gaps
2. `grep` for: API routes/handlers without `getSession`/`auth()`
3. Check server actions for session validation
4. Look for routes not covered by middleware

### Severity Assessment

- **Critical**: Admin functionality accessible without auth
- **High**: User data accessible without proper auth
- **Medium**: Auth bypass with limited scope
- **Low**: Informational endpoints exposed
"""
