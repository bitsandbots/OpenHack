"""
Supabase RPC function security detection prompt.
"""

SUPABASE_RPC_PROMPT = """## RPC Function Security in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.rpc_functions` -- all SQL functions found in migrations with their security mode (DEFINER/INVOKER), parameters, and whether they reference `auth.uid()`
- `supabase_recon.rpc_access` -- runtime test showing which RPC functions are callable by anon (with status codes)
- `supabase_recon.schema.functions` -- functions exposed via PostgREST OpenAPI spec

**Critical cross-reference: a function with `security_mode: "DEFINER"` + `has_auth_uid_check: False` + `callable: True` in `rpc_access` is likely a privilege escalation vector.**

### What to Look For

1. **SECURITY DEFINER without ownership checks**
   - `SECURITY DEFINER` functions execute with the privileges of the function owner (usually `postgres`), bypassing RLS entirely
   - If the function doesn't internally verify `auth.uid()`, any caller (including anon) can access/modify any data
   - This is the most common and dangerous Supabase misconfiguration

2. **Unsafe search_path**
   - Functions with `search_path` set to `public` or not set at all
   - Malicious users could create objects in the public schema that the function resolves instead of intended objects

3. **Client-supplied IDs trusted over JWT**
   - Function parameters like `p_user_id` used directly in queries instead of `auth.uid()`
   - Caller can pass any user ID to access other users' data

4. **Anon-callable sensitive functions**
   - Functions that should require authentication but are callable by the anon role
   - Check `supabase_recon.rpc_access` for functions with `callable: True`

### Vulnerable Patterns

```sql
-- VULNERABLE: SECURITY DEFINER with no auth check
CREATE OR REPLACE FUNCTION get_user_stats(p_user_id uuid)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Trusts client-supplied user_id, bypasses RLS
  RETURN (SELECT row_to_json(u) FROM users u WHERE u.id = p_user_id);
END;
$$;
```

```sql
-- VULNERABLE: Unsafe search_path
CREATE OR REPLACE FUNCTION admin_action()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public  -- Attacker can shadow objects in public schema
AS $$
BEGIN
  -- ...
END;
$$;
```

```sql
-- VULNERABLE: No ownership check, any user can call
CREATE OR REPLACE FUNCTION delete_account(p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  DELETE FROM users WHERE id = p_user_id;  -- Any anon user can delete any account!
END;
$$;
```

### Safe Patterns

```sql
-- SAFE: SECURITY INVOKER respects caller's RLS
CREATE OR REPLACE FUNCTION get_my_stats()
RETURNS json
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
  RETURN (SELECT row_to_json(u) FROM users u WHERE u.id = auth.uid());
END;
$$;
```

```sql
-- SAFE: DEFINER with explicit auth check and safe search_path
CREATE OR REPLACE FUNCTION admin_get_user(p_user_id uuid)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  -- Verify caller is admin
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = auth.uid() AND raw_user_meta_data->>'role' = 'admin') THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;
  RETURN (SELECT row_to_json(u) FROM public.users u WHERE u.id = p_user_id);
END;
$$;
```

### Search Patterns

1. Check `supabase_recon.rpc_functions` for `security_mode: "DEFINER"` + `has_auth_uid_check: False`
2. Cross-reference with `supabase_recon.rpc_access` for `callable: True`
3. `grep` migrations for `SECURITY DEFINER` to find all definer functions
4. `grep` for `search_path` settings in function definitions
5. Read function bodies to check for `auth.uid()` usage
6. For targeted probing: use `supabase_call_rpc` with foreign user IDs to test horizontal access

### Severity Assessment

- **Critical**: SECURITY DEFINER function callable by anon with no auth check, accessing sensitive data
- **High**: SECURITY DEFINER function callable by authenticated users but trusting client-supplied user_id
- **High**: Function with unsafe search_path allowing object shadowing
- **Medium**: Function missing tenant isolation checks
- **Low**: SECURITY INVOKER function with minor input validation gaps
"""
