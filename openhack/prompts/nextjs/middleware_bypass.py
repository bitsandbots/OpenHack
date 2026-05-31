"""
Next.js middleware bypass vulnerabilities detection prompt.
"""

NEXTJS_MIDDLEWARE_BYPASS_PROMPT = """## Next.js Middleware Bypass Vulnerabilities

### Path Normalization Issues

```typescript
// middleware.ts
export function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname;
  
  // VULNERABLE: Can be bypassed
  if (path.startsWith('/admin')) {
    // Bypass attempts:
    // - /Admin (case sensitivity)
    // - /admin/../admin (path traversal)
    // - /%61dmin (URL encoding)
    // - /admin. or /admin/ (trailing characters)
  }
}
```

### Matcher Pattern Gaps

```typescript
export const config = {
  // VULNERABLE patterns:
  matcher: '/api/:path*',           // Misses /api (no trailing path)
  matcher: ['/dashboard', '/admin'], // Misses /dashboard/settings
  
  // BETTER patterns:
  matcher: ['/api/:path*', '/api'],
  matcher: ['/(dashboard|admin)/:path*'],
};
```

### Static File Bypass

```typescript
// middleware.ts
export function middleware(req) {
  // VULNERABLE: Attackers can add _next/static to path
  // Request: /admin?_next/static/bypass
  if (req.nextUrl.pathname.includes('_next/static')) {
    return NextResponse.next(); // Bypass!
  }
}
```

### Rewrite/Redirect Issues

```typescript
// VULNERABLE: Redirect without validation
export function middleware(req) {
  const redirect = req.nextUrl.searchParams.get('redirect');
  return NextResponse.redirect(redirect); // Open redirect!
}
```

### Search Patterns

1. Read `middleware.ts` completely
2. Check matcher patterns for gaps
3. Look for path-based auth logic
4. Check for redirect/rewrite with user input

### Severity Assessment

- **Critical**: Auth bypass to admin areas
- **High**: Auth bypass to user data
- **Medium**: Bypass to non-sensitive areas
- **Low**: Minor path handling issues
"""
