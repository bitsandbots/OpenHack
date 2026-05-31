"""
Supabase GraphQL security detection prompt.
"""

SUPABASE_GRAPHQL_PROMPT = """## GraphQL Security in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.graphql.introspection_enabled` -- whether introspection queries succeed as anon
- `supabase_recon.graphql.types_count` -- number of types exposed
- `supabase_recon.schema` -- PostgREST schema (compare with GraphQL for parity drift)

**Key insight: Supabase GraphQL (pg_graphql) sits on top of Postgres with RLS. However, enforcement can drift between REST and GraphQL paths, and nested queries can expose data that direct queries wouldn't.**

### What to Look For

1. **Introspection enabled in production**
   - Introspection queries reveal the entire schema: tables, columns, types, relations
   - Check `supabase_recon.graphql.introspection_enabled`
   - While Supabase enables this by default, it exposes the attack surface

2. **Nested relation queries bypassing per-row checks**
   - GraphQL allows deep nesting: `{ users { orders { payments { ... } } } }`
   - RLS is applied per-table, but nested resolvers may not re-check ownership at each level
   - If `users` has RLS but `orders` doesn't, querying through `users->orders` may leak order data

3. **Global node IDs reusable across viewers**
   - pg_graphql provides global `nodeId` fields for relay-style pagination
   - If one user discovers a `nodeId`, they might query it directly as a different user
   - The `nodeId` encodes table and primary key, allowing targeted access

4. **REST vs GraphQL enforcement drift**
   - Protections applied at the REST/PostgREST level may not exist in the GraphQL path
   - Column restrictions, computed fields, or custom logic may differ between the two
   - Test the same query via both REST and GraphQL to check parity

5. **Deep nesting for resource exhaustion**
   - Deeply nested queries can cause expensive joins
   - No built-in query depth limiting in pg_graphql

### Vulnerable Patterns

```graphql
# VULNERABLE: Introspection reveals full schema
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
```

```graphql
# VULNERABLE: Deep nested query may bypass per-row checks
{
  usersCollection {
    edges {
      node {
        email
        ordersCollection {
          edges {
            node {
              amount
              paymentsCollection {
                edges {
                  node {
                    cardLast4
                    billingAddress
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### Search Patterns

1. Check `supabase_recon.graphql.introspection_enabled` for immediate finding
2. `grep` app code for `graphql`, `/graphql/v1`, `gql` template tags
3. Compare `supabase_recon.schema.tables` (REST) with GraphQL introspection types
4. Look for nested query patterns in application code
5. For targeted probing: use `supabase_graphql_query` with deep nested queries on tables that have RLS gaps

### Severity Assessment

- **Critical**: Nested GraphQL queries expose sensitive data that REST + RLS would block
- **High**: REST vs GraphQL enforcement drift allowing bypass via GraphQL path
- **Medium**: Introspection enabled revealing sensitive schema structure
- **Medium**: Global node IDs allowing cross-user targeted access
- **Low**: Deep nesting without depth limits (DoS potential)
"""
