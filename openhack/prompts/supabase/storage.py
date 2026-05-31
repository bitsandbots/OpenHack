"""
Supabase Storage security detection prompt.
"""

SUPABASE_STORAGE_PROMPT = """## Storage Security in Supabase

### Pre-Computed Recon Available

The `supabase_recon` context already contains:
- `supabase_recon.storage_policies.buckets` -- all storage buckets found in migrations with public/private status
- `supabase_recon.storage_policies.policies` -- RLS policies on `storage.objects`
- `supabase_recon.storage_access` -- runtime test showing which buckets are listable by anon

**Cross-reference: a bucket marked `public: True` in migrations + `listable: True` in `storage_access` that contains sensitive files is a finding.**

### What to Look For

1. **Public buckets with sensitive content**
   - Buckets marked as public serve files without authentication
   - If the bucket holds user uploads, documents, or exports, this is a data leak
   - Check bucket names: `documents`, `exports`, `reports`, `private`, `internal` suggest sensitive content

2. **Missing storage policies**
   - `storage.objects` has RLS just like regular tables
   - Without policies, default behavior depends on bucket public/private setting
   - Private buckets without policies may still be accessible via signed URLs that never expire

3. **Signed URL reuse across tenants/users**
   - Signed URLs generated for one user may be valid for any user
   - Check if URL generation includes user-specific scoping
   - Look for `createSignedUrl` calls without tenant/user path prefixes

4. **Content-type abuse**
   - Uploading HTML or SVG files that are served as `text/html` or `image/svg+xml`
   - These can contain JavaScript and enable XSS attacks
   - Check for `Content-Type` validation on upload and `X-Content-Type-Options: nosniff` on download

5. **Path confusion**
   - Mixed case, URL-encoding, or `..` segments may bypass client-side validation
   - Server and client may normalize paths differently
   - Users might access files outside their intended directory

6. **Bucket listing exposure**
   - `storage.from('bucket').list()` without authentication exposes file inventory
   - Even if individual files are protected, knowing the file names/paths is information disclosure

### Vulnerable Patterns

```sql
-- VULNERABLE: Public bucket for sensitive documents
INSERT INTO storage.buckets (id, name, public) VALUES ('documents', 'documents', true);
-- No policies on storage.objects for this bucket
```

```typescript
// VULNERABLE: Generating signed URLs without user scoping
const { data } = await supabase.storage
  .from('documents')
  .createSignedUrl('reports/financial-report.pdf', 3600)
// This URL works for anyone who has it, no user verification
```

```typescript
// VULNERABLE: No content-type validation on upload
const { error } = await supabase.storage
  .from('avatars')
  .upload(`${userId}/avatar`, file)
// User could upload malicious.html as their "avatar"
```

### Safe Patterns

```sql
-- SAFE: Private bucket with user-scoped policies
INSERT INTO storage.buckets (id, name, public) VALUES ('documents', 'documents', false);
CREATE POLICY "users_access_own_documents" ON storage.objects
  FOR ALL USING (bucket_id = 'documents' AND auth.uid()::text = (storage.foldername(name))[1]);
```

```typescript
// SAFE: User-scoped upload path with content-type validation
const allowedTypes = ['image/jpeg', 'image/png', 'image/webp']
if (!allowedTypes.includes(file.type)) throw new Error('Invalid file type')

const { error } = await supabase.storage
  .from('avatars')
  .upload(`${user.id}/avatar.${ext}`, file, {
    contentType: file.type,
    upsert: true,
  })
```

### Search Patterns

1. Check `supabase_recon.storage_policies.buckets` for `public: True` buckets
2. Cross-reference with `supabase_recon.storage_access` for `listable: True` buckets
3. `grep` migrations for `storage.buckets` and `storage.objects` to find all bucket/policy definitions
4. `grep` app code for `createSignedUrl`, `getPublicUrl`, `.upload(` to find storage usage
5. Check for content-type validation near upload calls
6. For targeted probing: use `supabase_probe_storage` to list specific bucket paths

### Severity Assessment

- **Critical**: Public bucket containing PII, financial data, or credentials
- **High**: Private bucket with missing storage policies allowing unauthorized access
- **High**: Signed URLs reusable across users/tenants for sensitive files
- **Medium**: Content-type abuse potential (HTML/SVG uploads served as text/html)
- **Medium**: Bucket listing exposes file inventory
- **Low**: Public bucket for intentionally public assets (logos, public images)
"""
