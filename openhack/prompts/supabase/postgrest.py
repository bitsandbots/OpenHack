"""
Supabase PostgREST and REST API vulnerability detection prompt.
"""

SUPABASE_POSTGREST_PROMPT = """## PostgREST / REST API Vulnerabilities in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.anon_access` -- which tables the anon role can SELECT/INSERT/UPDATE/DELETE
- `supabase_recon.schema.columns` -- column names per table (from OpenAPI spec)
- `supabase_recon.schema.tables` -- all tables exposed via PostgREST

**Start by reviewing `anon_access` for tables with unexpected access permissions.** Any table where anon can read or write is a potential finding.

### What to Look For

1. **IDOR via direct row access**
   - Tables accessible by anon where rows can be fetched by ID
   - No ownership filter means any row is accessible: `/rest/v1/orders?id=eq.<any_id>`
   - Check if `supabase_recon.query_patterns` shows `.from('table').select()` without `.eq('user_id', ...)`

2. **Filter abuse for data extraction**
   - `or` filters: `?or=(user_id.eq.X,user_id.is.null)` to bypass intended scoping
   - `ilike` filters: `?email=ilike.*@company.com` for wildcard enumeration
   - `neq` filters: `?role=neq.admin` to probe for admin rows
   - Combine filters to extract data column by column

3. **Relation embedding overfetch**
   - PostgREST allows embedding related tables: `?select=*,profile(*),orders(*)`
   - If the parent table has RLS but the embedded table doesn't, data leaks through the join
   - Check for foreign key relationships between protected and unprotected tables

4. **Mass assignment via PATCH/POST**
   - If anon or authenticated users can INSERT/UPDATE, they may modify unintended columns
   - Example: setting `role`, `is_admin`, `org_id` via PATCH when only `name` was intended
   - Check if the app uses RPC functions for writes instead of direct table access

5. **Count-based blind enumeration**
   - `Prefer: count=exact` header returns total row count even with `limit=0`
   - Can enumerate total records in a table without reading actual data
   - Use `supabase_query_table` with `count: "exact"` to test

6. **Schema exposure**
   - PostgREST OpenAPI spec reveals table names, column names, types, and foreign keys
   - `supabase_recon.schema` already has this data -- check for sensitive column names

### Vulnerable Application Code Patterns

```typescript
// VULNERABLE: No ownership filter, any user can read all orders
const { data } = await supabase
  .from('orders')
  .select('*')

// VULNERABLE: Client-controlled filter that can be bypassed
const { data } = await supabase
  .from('users')
  .select('*')
  .eq('id', params.id)  // User controls the ID
```

```typescript
// VULNERABLE: Embedding exposes related data
const { data } = await supabase
  .from('posts')
  .select('*, author:users(*), comments(*)')
  // If users table has weaker RLS than posts, author data leaks
```

### Safe Patterns

```typescript
// SAFE: Server-side ownership filter using authenticated user
const { data: { user } } = await supabase.auth.getUser()
const { data } = await supabase
  .from('orders')
  .select('*')
  .eq('user_id', user.id)
```

### Search Patterns

1. Check `supabase_recon.anon_access` for tables with `select: True` or `insert: True`
2. Check `supabase_recon.schema.columns` for sensitive column names (email, password, ssn, token, secret)
3. `grep` app code for `.from(` calls without subsequent `.eq('user_id'` or ownership filters
4. Look for `select('*,` patterns that embed related tables
5. For targeted probing: use `supabase_query_table` with filter combinations to test data extraction
6. For write testing: use `supabase_mutate_table` to test mass assignment

### Severity Assessment

- **Critical**: Anon can read sensitive data (PII, financial) from tables with no RLS
- **High**: Anon can write to tables (INSERT/UPDATE), enabling data manipulation
- **High**: Filter abuse allows extraction of data that should be scoped per-user
- **Medium**: Schema exposure reveals sensitive table/column structure
- **Medium**: Count-based enumeration reveals record counts
- **Low**: Non-sensitive public data accessible (may be intentional)
"""
