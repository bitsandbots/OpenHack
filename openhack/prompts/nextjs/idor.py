"""
Next.js IDOR (Insecure Direct Object Reference) detection prompt.
"""

NEXTJS_IDOR_PROMPT = """## IDOR (Insecure Direct Object Reference) Detection in Next.js

### What to Look For

1. **Route parameters used directly in database queries**
   - App Router: `params.id` in route handlers or server components
   - Pages Router: `req.query.id` in API routes
   
2. **Missing ownership verification**
   - User can access resources belonging to other users
   - No check that `resource.userId === session.userId`

3. **Predictable IDs**
   - Sequential numeric IDs (1, 2, 3...)
   - UUIDs are safer but not sufficient alone

### Next.js Specific Patterns

**App Router (Vulnerable)**:
```typescript
// app/api/users/[id]/route.ts
export async function GET(req: Request, { params }: { params: { id: string } }) {
  // VULNERABLE: No auth check, direct ID usage
  const user = await db.user.findUnique({ where: { id: params.id } });
  return Response.json(user);
}
```

**Pages Router (Vulnerable)**:
```typescript
// pages/api/posts/[id].ts
export default async function handler(req, res) {
  // VULNERABLE: Anyone can access any post by ID
  const post = await prisma.post.findUnique({ where: { id: req.query.id } });
  res.json(post);
}
```

**Server Actions (Vulnerable)**:
```typescript
'use server'
async function getDocument(documentId: string) {
  // VULNERABLE: No ownership check
  return await db.document.findUnique({ where: { id: documentId } });
}
```

### Search Patterns

1. `grep` for: `params\\.\\w+`, `req\\.query`, `searchParams\\.get`
2. Check if these values go directly to database queries
3. Look for missing session/auth checks before the query

### Severity Assessment

- **Critical**: Access to other users' sensitive data (PII, financial)
- **High**: Access to other users' content/resources
- **Medium**: Access to metadata or non-sensitive resources
- **Low**: Informational leaks with no security impact
"""
