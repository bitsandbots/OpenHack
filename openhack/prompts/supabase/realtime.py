"""
Supabase Realtime security detection prompt.
"""

SUPABASE_REALTIME_PROMPT = """## Realtime Security in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.anon_access` -- tables accessible by anon (if anon can SELECT, realtime changes likely also leak)
- `supabase_recon.rls_policies` -- RLS status per table (realtime respects RLS for postgres_changes)

**Key insight: Realtime postgres_changes subscriptions are governed by the same RLS policies as direct table access. If a table has no RLS or permissive RLS, realtime will leak every change to any subscriber.**

### What to Look For

1. **Subscriptions to tables without RLS**
   - `supabase.channel('*').on('postgres_changes', { table: 'orders' }, ...)` on a table without RLS
   - Every INSERT/UPDATE/DELETE on that table is broadcast to all subscribers including anon
   - Cross-reference: if `anon_access[table].select` is True, realtime changes are also exposed

2. **Broadcast/presence channels without authentication**
   - Broadcast and presence channels don't go through RLS
   - Channel names derived from guessable IDs: `room:${userId}`, `org:${orgId}`
   - Any client can join any channel name and receive/send messages

3. **Sensitive data in realtime payloads**
   - Even with RLS, the `NEW` and `OLD` records in change events include all columns
   - If the table has sensitive columns (passwords, tokens, secrets), they leak via realtime
   - Check if the subscription uses column filtering

4. **Cross-room join/publish**
   - Broadcast channels: client can publish to any channel they can join
   - If channel names encode authorization (e.g., `admin-updates`), any client can subscribe

### Vulnerable Patterns

```typescript
// VULNERABLE: Subscribing to table without RLS
supabase
  .channel('orders-changes')
  .on('postgres_changes',
    { event: '*', schema: 'public', table: 'orders' },
    (payload) => {
      console.log('Change received:', payload)
      // Receives ALL changes to orders table from ALL users
    }
  )
  .subscribe()
```

```typescript
// VULNERABLE: Guessable channel name without auth verification
supabase
  .channel(`user:${otherUserId}`)  // Can join any user's channel
  .on('broadcast', { event: 'notification' }, (payload) => {
    // Receives another user's notifications
  })
  .subscribe()
```

### Safe Patterns

```typescript
// SAFE: Table has proper RLS, so only authorized changes are received
// (Assuming orders table has: USING (auth.uid() = user_id) policy)
supabase
  .channel('my-orders')
  .on('postgres_changes',
    { event: '*', schema: 'public', table: 'orders',
      filter: `user_id=eq.${user.id}` },
    (payload) => {
      // Only receives changes for current user's orders
    }
  )
  .subscribe()
```

### Search Patterns

1. Check `supabase_recon.rls_policies.tables_without_rls` -- any table subscribed to via realtime is vulnerable
2. `grep` app code for `.channel(`, `.on('postgres_changes'`, `.on('broadcast'`, `.subscribe(`
3. Check channel name patterns for guessable IDs
4. Cross-reference subscribed tables with `supabase_recon.anon_access`
5. Look for `filter:` parameter in postgres_changes subscriptions (reduces exposure but doesn't replace RLS)

### Severity Assessment

- **Critical**: Realtime subscription on sensitive table without RLS, leaking all changes to anon
- **High**: Broadcast/presence channels with guessable names exposing user-specific data
- **Medium**: Realtime subscription includes sensitive columns even with RLS
- **Low**: Realtime on intentionally public data (e.g., public chat, live scores)
"""
