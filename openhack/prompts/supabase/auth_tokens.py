"""
Supabase Auth, JWT, and service_role key exposure detection prompt.
"""

SUPABASE_AUTH_PROMPT = """## Auth & JWT Security in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.clients` -- all Supabase client initializations with `uses_service_role` flag
- `supabase_recon.config.env_vars` -- Supabase-related environment variable names found in the codebase
- `supabase_recon.edge_functions` -- Edge Functions with `uses_service_role` flag

**Immediate critical findings:**
- Any entry in `clients` with `uses_service_role: True` in a client-side file (e.g., under `app/`, `pages/`, `components/`, or any file imported by client code)
- `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` in `config.env_vars` (service role key exposed to browser via Next.js public env var)

### What to Look For

1. **service_role key exposed in client code**
   - The `service_role` key bypasses ALL RLS policies -- it's the master key
   - Must NEVER appear in client-side code, browser bundles, or public env vars
   - Check: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`, `VITE_SUPABASE_SERVICE_ROLE_KEY`
   - Check: `createClient(url, serviceRoleKey)` in files served to the browser

2. **Hardcoded keys in source code**
   - API keys, service role keys, or JWT secrets committed to the repository
   - `grep` for long base64 strings near Supabase client initialization
   - Check `.env.local`, `.env.example`, `.env` files for real key values

3. **getSession() vs getUser() confusion**
   - `getSession()` reads the session from local storage -- it is NOT authenticated by the server
   - An attacker can forge the session in localStorage and `getSession()` will trust it
   - `getUser()` makes a server call to verify the JWT -- this is the safe method
   - Server-side code should always use `getUser()` for authorization decisions

4. **JWT stored in localStorage**
   - Tokens in localStorage are accessible to any JavaScript on the page (XSS-exfiltrable)
   - Supabase stores tokens in localStorage by default
   - If the app has any XSS vulnerability, auth tokens can be stolen

5. **Missing audience/issuer verification**
   - Custom endpoints that accept JWTs should verify `iss` (issuer) and `aud` (audience)
   - Tokens from one Supabase project should not work on another
   - Edge Functions should not trust the `Authorization` header without verification

6. **apikey treated as identity**
   - The `apikey` header identifies the project, NOT the user
   - The anon key is public and project-scoped
   - Code that checks for `apikey` presence as an auth mechanism is vulnerable

7. **Refresh token mismanagement**
   - Long-lived refresh tokens that never expire
   - Refresh tokens not rotated after use
   - Revocation not implemented for compromised tokens

### Vulnerable Patterns

```typescript
// VULNERABLE: service_role key in client-side code
import { createClient } from '@supabase/supabase-js'
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!  // EXPOSED TO BROWSER!
)
```

```typescript
// VULNERABLE: Using getSession() for authorization
export async function GET() {
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) return new Response('Unauthorized', { status: 401 })
  // session could be forged from localStorage!
  const userId = session.user.id  // CANNOT BE TRUSTED
  const data = await supabase.from('orders').select().eq('user_id', userId)
  return Response.json(data)
}
```

```typescript
// VULNERABLE: Treating apikey as authentication
export async function middleware(req) {
  const apiKey = req.headers.get('apikey')
  if (!apiKey) return new Response('Unauthorized', { status: 401 })
  // apikey is public! This is NOT authentication
}
```

### Safe Patterns

```typescript
// SAFE: service_role key only in server-side code
// lib/supabase/admin.ts (never imported by client code)
import { createClient } from '@supabase/supabase-js'
export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,           // No NEXT_PUBLIC_ prefix
  process.env.SUPABASE_SERVICE_ROLE_KEY! // No NEXT_PUBLIC_ prefix
)
```

```typescript
// SAFE: Using getUser() for authorization
export async function GET() {
  const { data: { user }, error } = await supabase.auth.getUser()
  if (error || !user) return new Response('Unauthorized', { status: 401 })
  // user.id is verified by the server
  const data = await supabase.from('orders').select().eq('user_id', user.id)
  return Response.json(data)
}
```

### Search Patterns

1. Check `supabase_recon.clients` for `uses_service_role: True` -- inspect the file path to determine if client-side
2. Check `supabase_recon.config.env_vars` for `NEXT_PUBLIC_*SERVICE_ROLE*` or `VITE_*SERVICE_ROLE*`
3. `grep` for `service_role`, `serviceRole`, `SUPABASE_SERVICE_ROLE` in all files
4. `grep` for `getSession` in server-side files (API routes, server components, middleware) -- should be `getUser`
5. `grep` for `localStorage` near token storage/retrieval
6. `grep` for hardcoded JWT-like strings (long base64 with dots: `eyJ...`)
7. Check `.env*` files for real key values committed to repo

### Severity Assessment

- **Critical**: service_role key exposed in client bundle or public env var
- **Critical**: Hardcoded service_role key in committed source code
- **High**: Using `getSession()` instead of `getUser()` for server-side authorization
- **High**: Custom endpoints accepting JWTs without audience/issuer verification
- **Medium**: JWT tokens stored in localStorage (XSS risk)
- **Medium**: apikey header used as authentication mechanism
- **Low**: Refresh token configuration concerns
"""
