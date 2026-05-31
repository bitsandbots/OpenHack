"""
Supabase Row Level Security (RLS) misconfiguration detection prompt.
"""

SUPABASE_RLS_PROMPT = """## Row Level Security (RLS) Misconfigurations in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains the results of deterministic RLS analysis:
- `supabase_recon.rls_policies.tables_without_rls` -- tables that have NO RLS enabled in migrations
- `supabase_recon.rls_policies.tables` -- all tables with their RLS status and policy details
- `supabase_recon.anon_access` -- runtime test results showing which tables the anon role can actually read/write

**Start by cross-referencing these two datasets.** A table with no RLS in migrations AND `select: True` in `anon_access` is an instant critical finding.

### What to Look For

1. **Tables without RLS enabled**
   - Every non-public table must have `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
   - Absence means the table is wide open to any role with access

2. **Overly permissive policies**
   - `using (true)` or `with check (true)` grants unrestricted access
   - Policies that don't reference `auth.uid()` or a tenant column

3. **Per-operation gaps**
   - SELECT policy exists but UPDATE/DELETE/INSERT policies are missing
   - A table may be read-protected but write-open (or vice versa)

4. **Policies trusting client-supplied data**
   - Policy checks `user_id` column (which can be set by the client on INSERT) instead of `auth.uid()` from the JWT
   - Example: `using (user_id = auth.uid())` on SELECT is fine, but `with check (user_id = auth.uid())` on INSERT trusts whatever the client sends as `user_id` if not also constrained

5. **Missing tenant/org constraints**
   - Multi-tenant apps must scope every policy to `org_id`/`tenant_id`
   - Missing tenant constraint allows cross-tenant data access

6. **Complex join inference**
   - Even with RLS, count-based queries (`Prefer: count=exact`) can leak information about rows the user shouldn't see
   - Policies applied after filters can allow inference via response timing or counts

### Vulnerable Migration Patterns

```sql
-- VULNERABLE: Table created with NO RLS
CREATE TABLE orders (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid REFERENCES auth.users(id),
  amount numeric,
  status text
);
-- Missing: ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
-- Missing: CREATE POLICY ... ON orders ...
```

```sql
-- VULNERABLE: RLS enabled but permit-all policy
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow_all" ON documents FOR ALL USING (true);
```

```sql
-- VULNERABLE: SELECT policy exists, but no INSERT/UPDATE/DELETE policies
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_read_own" ON profiles FOR SELECT USING (auth.uid() = id);
-- No INSERT/UPDATE/DELETE policies = default deny, but could be intentionally missing
-- or could be a gap if the app needs write access
```

```sql
-- VULNERABLE: Policy trusts client-supplied user_id on INSERT
CREATE POLICY "users_insert" ON posts FOR INSERT
  WITH CHECK (user_id = auth.uid());
-- If user_id is in the INSERT payload, client can set user_id = auth.uid() trivially
-- But what about other columns like org_id, role, etc.?
```

### Safe Patterns

```sql
-- SAFE: Proper RLS with per-operation policies
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_read_own_orders" ON orders FOR SELECT
  USING (auth.uid() = user_id);
CREATE POLICY "users_insert_own_orders" ON orders FOR INSERT
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY "users_update_own_orders" ON orders FOR UPDATE
  USING (auth.uid() = user_id);
CREATE POLICY "users_delete_own_orders" ON orders FOR DELETE
  USING (auth.uid() = user_id);
```

### Search Patterns

1. Check `supabase_recon.rls_policies.tables_without_rls` for immediate findings
2. Cross-reference with `supabase_recon.anon_access` to confirm runtime exposure
3. `grep` migration files for `using (true)` and `with check (true)`
4. Check policies for `auth.uid()` references -- policies without it are suspicious
5. Look for tables with SELECT policy but missing UPDATE/DELETE/INSERT policies
6. For targeted probing: use `supabase_query_table` with filters like `or=(user_id.eq.X,user_id.is.null)` to test policy enforcement

### Severity Assessment

- **Critical**: Table without RLS + anon can read/write data at runtime (confirmed by `anon_access`)
- **Critical**: Sensitive table (users, payments, PII) with `using (true)` policy
- **High**: RLS enabled but policy is overly permissive or missing for some operations
- **High**: Policy trusts client-supplied columns instead of JWT context
- **Medium**: Missing tenant isolation in multi-tenant app
- **Low**: RLS gap on non-sensitive, intentionally public data
"""
