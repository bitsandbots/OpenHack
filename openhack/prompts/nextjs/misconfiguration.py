"""
Next.js security misconfigurations detection prompt.
"""

NEXTJS_MISCONFIGURATION_PROMPT = """## Security Misconfigurations in Next.js

### Security Headers

**next.config.js**:
```javascript
// Check for security headers
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          // SHOULD HAVE:
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Content-Security-Policy', value: "default-src 'self'" },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
        ],
      },
    ];
  },
};
```

### CORS Configuration

```typescript
// VULNERABLE: Wildcard CORS
export async function GET(req: Request) {
  return new Response(data, {
    headers: {
      'Access-Control-Allow-Origin': '*', // Too permissive!
      'Access-Control-Allow-Credentials': 'true', // Dangerous with *
    },
  });
}
```

### Exposed .next Directory

Check if `.next` directory is accessible:
- `/.next/server/pages-manifest.json`
- `/.next/BUILD_ID`

### Debug Mode in Production

```javascript
// next.config.js
module.exports = {
  // VULNERABLE in production:
  reactStrictMode: false,
  productionBrowserSourceMaps: true, // Exposes source code!
};
```

### Insecure redirects/rewrites

```javascript
// next.config.js
module.exports = {
  async redirects() {
    return [
      {
        source: '/redirect',
        destination: '/:path*', // VULNERABLE: Open redirect potential
        permanent: false,
      },
    ];
  },
};
```

### Search Patterns

1. Read `next.config.js` completely
2. Check for security headers configuration
3. Look for CORS settings in API routes
4. Check for `productionBrowserSourceMaps`
5. Review redirect/rewrite rules

### Severity Assessment

- **High**: Missing critical security headers, wildcard CORS with credentials
- **Medium**: Missing some headers, overly permissive CORS
- **Low**: Missing optional headers, minor misconfigurations
"""
