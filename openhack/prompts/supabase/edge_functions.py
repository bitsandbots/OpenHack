"""
Supabase Edge Functions security detection prompt.
"""

SUPABASE_EDGE_FUNCTIONS_PROMPT = """## Edge Functions Security in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.edge_functions` -- all discovered Edge Functions with `uses_service_role`, `has_cors`, `has_auth_check`, `has_jwt_verification` flags

**Immediate findings: any Edge Function with `uses_service_role: True` + `has_auth_check: False` is high risk -- it has full database access but doesn't verify who's calling it.**

### What to Look For

1. **service_role usage without JWT verification**
   - Edge Functions commonly initialize Supabase with `SUPABASE_SERVICE_ROLE_KEY` for admin operations
   - If the function doesn't verify the caller's JWT, anyone can trigger admin-level database operations
   - The function must extract and verify the JWT from the `Authorization` header

2. **CORS misconfiguration**
   - Wildcard `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`
   - Reflected `Origin` header in `Access-Control-Allow-Origin` without validation
   - Missing CORS headers allowing any origin to call the function

3. **SSRF via fetch()**
   - Edge Functions can make outbound HTTP requests
   - If the URL is controlled by user input, the function can be used to probe internal services
   - Metadata service access: `http://169.254.169.254/` or cloud provider metadata endpoints

4. **Secrets in error traces or logs**
   - Error responses that include stack traces with environment variable values
   - `console.log` or `console.error` dumping request/response bodies containing secrets
   - Service role key or other secrets appearing in response bodies on error

5. **Not re-deriving user from JWT**
   - Trusting `user_id` or `tenant_id` from the request body instead of extracting from JWT
   - The function should parse the JWT to get the authenticated user identity

6. **Missing auth on function invocation**
   - Edge Functions accessible without any Authorization header
   - No validation that the caller is authenticated at all

### Vulnerable Patterns

```typescript
// supabase/functions/process-order/index.ts
// VULNERABLE: service_role with no auth check
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

Deno.serve(async (req) => {
  const { orderId, userId } = await req.json()

  // Uses service_role (bypasses all RLS)
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  )

  // Trusts client-supplied userId instead of extracting from JWT
  const { data } = await supabase
    .from('orders')
    .update({ status: 'processed' })
    .eq('id', orderId)
    .eq('user_id', userId)  // Client controls this!

  return new Response(JSON.stringify(data))
})
```

```typescript
// VULNERABLE: Wildcard CORS with credentials
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Credentials': 'true',  // Dangerous with wildcard origin!
}
```

```typescript
// VULNERABLE: SSRF via user-controlled URL
Deno.serve(async (req) => {
  const { webhookUrl, data } = await req.json()
  const response = await fetch(webhookUrl, {  // User controls the URL!
    method: 'POST',
    body: JSON.stringify(data),
  })
  return new Response(JSON.stringify({ status: response.status }))
})
```

### Safe Patterns

```typescript
// SAFE: Verify JWT before using service_role
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

Deno.serve(async (req) => {
  // Verify the caller's JWT
  const authHeader = req.headers.get('Authorization')
  if (!authHeader) {
    return new Response('Missing authorization', { status: 401 })
  }

  // Create a user-context client to verify the token
  const supabaseUser = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_ANON_KEY')!,
    { global: { headers: { Authorization: authHeader } } }
  )

  const { data: { user }, error } = await supabaseUser.auth.getUser()
  if (error || !user) {
    return new Response('Invalid token', { status: 401 })
  }

  // Now use service_role for admin operations, scoped to verified user
  const supabaseAdmin = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  )

  const { data } = await supabaseAdmin
    .from('orders')
    .update({ status: 'processed' })
    .eq('user_id', user.id)  // user.id from verified JWT

  return new Response(JSON.stringify(data))
})
```

### Search Patterns

1. Check `supabase_recon.edge_functions` for `uses_service_role: True` + `has_auth_check: False`
2. Read each Edge Function file (`supabase/functions/*/index.ts`)
3. `grep` for `SUPABASE_SERVICE_ROLE_KEY`, `Deno.env.get`, `createClient`
4. `grep` for `Access-Control-Allow-Origin` and CORS patterns
5. `grep` for `fetch(` with dynamic URLs (SSRF risk)
6. Check for `Authorization` header extraction and JWT verification
7. Look for `req.json()` fields used directly as user identity

### Severity Assessment

- **Critical**: Edge Function with service_role and no auth, performing data mutations
- **High**: Edge Function trusting client-supplied user IDs with service_role
- **High**: SSRF via user-controlled fetch URLs
- **Medium**: CORS wildcard with credentials
- **Medium**: Secrets leaked in error responses
- **Low**: Missing rate limiting on function invocation
"""
