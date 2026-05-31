"""
Next.js server actions security detection prompt.
"""

NEXTJS_SERVER_ACTIONS_PROMPT = """## Server Actions Security in Next.js

### What to Look For

1. **Missing input validation**
2. **Missing authentication checks**
3. **Mass assignment vulnerabilities**
4. **Race conditions**

### Authentication in Server Actions

```typescript
'use server'

// VULNERABLE: No auth check
export async function deletePost(postId: string) {
  await db.post.delete({ where: { id: postId } });
}

// SAFE: Auth check
export async function deletePost(postId: string) {
  const session = await auth();
  if (!session) throw new Error('Unauthorized');
  
  const post = await db.post.findUnique({ where: { id: postId } });
  if (post.authorId !== session.user.id) throw new Error('Forbidden');
  
  await db.post.delete({ where: { id: postId } });
}
```

### Input Validation

```typescript
'use server'

// VULNERABLE: No validation
export async function updateUser(data: FormData) {
  const name = data.get('name');
  const email = data.get('email');
  await db.user.update({ 
    where: { id: session.userId },
    data: { name, email } // What if email is malicious?
  });
}

// SAFE: Validate with Zod
import { z } from 'zod';
const schema = z.object({
  name: z.string().min(1).max(100),
  email: z.string().email(),
});

export async function updateUser(data: FormData) {
  const validated = schema.parse({
    name: data.get('name'),
    email: data.get('email'),
  });
  // ...
}
```

### Mass Assignment

```typescript
'use server'

// VULNERABLE: Spreading all form data
export async function updateProfile(data: FormData) {
  const updates = Object.fromEntries(data);
  await db.user.update({
    where: { id: session.userId },
    data: updates, // User could add: role: 'admin'!
  });
}
```

### Search Patterns

1. `grep` for: `'use server'` and `"use server"`
2. Check each server action for:
   - Session/auth validation
   - Input validation (zod, yup, etc.)
   - Ownership checks on resources
3. Look for `Object.fromEntries` or spread operators with form data

### Severity Assessment

- **Critical**: Unauthenticated server actions modifying data
- **High**: Missing authorization checks (IDOR via server actions)
- **Medium**: Missing input validation with limited impact
- **Low**: Minor validation gaps
"""
