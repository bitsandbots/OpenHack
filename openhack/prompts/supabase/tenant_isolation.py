"""
Supabase tenant isolation security detection prompt.
"""

SUPABASE_TENANT_ISOLATION_PROMPT = """## Tenant Isolation in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.query_patterns` -- all `.from()` calls with `has_ownership_filter` and `has_tenant_filter` flags
- `supabase_recon.rls_policies` -- RLS policies and whether they reference tenant columns
- `supabase_recon.anon_access` -- which tables anon can access (cross-tenant probing surface)

**Key insight: in multi-tenant Supabase apps, every query AND every RLS policy must be scoped by `tenant_id`/`org_id`/`team_id` derived from the JWT, NOT from client input.**

### What to Look For

1. **Queries not scoped by tenant**
   - Application code querying tables without filtering by `org_id`/`tenant_id`
   - Check `supabase_recon.query_patterns` for `has_tenant_filter: False`
   - Even with RLS, application-level scoping is defense in depth

2. **RLS policies trusting client-supplied tenant context**
   - Policy uses `org_id` column value that the client can set on INSERT
   - Instead of: `USING (org_id = (auth.jwt() -> 'app_metadata' ->> 'org_id')::uuid)`
   - Wrong: `USING (org_id = org_id)` (tautology, always true)

3. **Tenant selector inconsistent with JWT**
   - App determines tenant from subdomain, header, or path parameter
   - But JWT encodes a different tenant claim
   - User from tenant A can switch subdomain to tenant B and access their data

4. **Export/report endpoints outside caller scope**
   - Endpoints that generate CSV exports, PDF reports, or aggregations
   - If the query doesn't filter by tenant from JWT, it may include cross-tenant data
   - Check server-side code for export/report generation

5. **Cross-tenant probing via filters**
   - Using `or` filters: `?or=(org_id.eq.other_org,org_id.is.null)`
   - Filtering by another org's ID: `?org_id=eq.foreign_org_id`
   - If RLS doesn't enforce tenant isolation, these queries return cross-tenant data

### Vulnerable Patterns

```typescript
// VULNERABLE: No tenant scoping on query
const { data } = await supabase
  .from('projects')
  .select('*')
  // Missing: .eq('org_id', user.org_id)
  // Returns ALL projects across ALL tenants
```

```sql
-- VULNERABLE: RLS policy without tenant constraint
CREATE POLICY "users_access" ON projects
  FOR SELECT USING (auth.uid() = created_by);
-- Missing org_id check -- user can see projects from other orgs
-- if they happen to be created_by (unlikely but possible in edge cases)
```

```typescript
// VULNERABLE: Tenant from URL, not JWT
export async function GET(req, { params }) {
  const orgId = params.orgId  // From URL path, client-controlled!
  const { data } = await supabase
    .from('projects')
    .select('*')
    .eq('org_id', orgId)  // Client picks which org to access
}
```

```sql
-- VULNERABLE: Policy with tautological check
CREATE POLICY "org_access" ON documents
  FOR SELECT USING (org_id = org_id);  -- Always true!
```

### Safe Patterns

```sql
-- SAFE: RLS policy scoped to tenant from JWT
CREATE POLICY "tenant_isolation" ON projects
  FOR ALL USING (
    org_id = (auth.jwt() -> 'app_metadata' ->> 'org_id')::uuid
  );
```

```typescript
// SAFE: Tenant derived from verified JWT, not client input
const { data: { user } } = await supabase.auth.getUser()
const orgId = user.app_metadata.org_id  // From verified JWT

const { data } = await supabase
  .from('projects')
  .select('*')
  .eq('org_id', orgId)
```

### Search Patterns

1. Check `supabase_recon.query_patterns` for `has_tenant_filter: False` on multi-tenant tables
2. `grep` for `org_id`, `tenant_id`, `team_id`, `workspace_id` in RLS policies
3. `grep` app code for `.eq('org_id'` to see how tenant is derived (from JWT vs URL/header)
4. Look for export/report endpoints (`/api/export`, `/api/report`, `csv`, `download`)
5. Check RLS policies for tautological conditions
6. For targeted probing: use `supabase_query_table` with `org_id=eq.foreign-org` to test isolation

### Severity Assessment

- **Critical**: Cross-tenant data access confirmed via runtime probing
- **Critical**: Sensitive data (financial, PII) accessible across tenants
- **High**: RLS policies missing tenant constraints in multi-tenant app
- **High**: Tenant derived from client input (URL/header) instead of JWT
- **Medium**: Export endpoints generating unscoped reports
- **Medium**: Application queries missing tenant filters (defense in depth gap)
- **Low**: Tenant isolation relies solely on RLS (no application-level check)
"""
