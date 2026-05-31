"""
Next.js SSRF (Server-Side Request Forgery) detection prompt.
"""

NEXTJS_SSRF_PROMPT = """## SSRF (Server-Side Request Forgery) Detection in Next.js

### What to Look For

1. **User-controlled URLs in server-side fetch/axios calls**
2. **URL parameters used in API requests**
3. **Image/file fetching from user-provided URLs**

### Next.js Specific Patterns

**Route Handlers / API Routes**:
```typescript
// VULNERABLE: User-controlled URL
export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get('url');
  const response = await fetch(url); // SSRF!
  return Response.json(await response.json());
}
```

**Server Components**:
```typescript
// VULNERABLE: URL from searchParams used in fetch
async function Page({ searchParams }) {
  const data = await fetch(searchParams.apiUrl); // SSRF!
  return <div>{data}</div>;
}
```

**Image Optimization**:
```typescript
// next.config.js - Check remotePatterns
module.exports = {
  images: {
    // VULNERABLE: Too permissive
    remotePatterns: [{ protocol: 'https', hostname: '**' }],
  },
};
```

**Webhook Handlers**:
```typescript
// VULNERABLE: Fetching user-provided callback URL
async function handleWebhook(callbackUrl: string, data: any) {
  await fetch(callbackUrl, { method: 'POST', body: JSON.stringify(data) });
}
```

### Search Patterns

1. `grep` for: `fetch\\(.*(?:req|params|query|searchParams)`
2. `grep` for: `axios\\.(?:get|post)\\(.*(?:req|params|query)`
3. `grep` for: URL construction with user input
4. Check `next.config.js` for `images.remotePatterns`

### Severity Assessment

- **Critical**: Can reach internal services, cloud metadata (169.254.169.254)
- **High**: Can scan internal network, access internal APIs
- **Medium**: Limited internal access, some filtering in place
- **Low**: External SSRF only, minimal impact
"""
