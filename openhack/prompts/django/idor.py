"""
Django IDOR (Insecure Direct Object Reference) detection prompt.
"""

DJANGO_IDOR_PROMPT = """## IDOR (Insecure Direct Object Reference) Detection in Django

### What to Look For

1. **URL parameters used directly in queries without ownership checks**
2. **DRF ViewSets without get_queryset scoping**
3. **Missing filter_by(user=request.user) on object lookups**

### Django-Specific Patterns

**Function-Based Views (Vulnerable)**:
```python
# VULNERABLE: No ownership check
def view_invoice(request, invoice_id):
    invoice = get_object_or_404(Invoice, pk=invoice_id)
    return render(request, "invoice.html", {"invoice": invoice})

# SAFE: Scoped to user
def view_invoice(request, invoice_id):
    invoice = get_object_or_404(Invoice, pk=invoice_id, user=request.user)
    return render(request, "invoice.html", {"invoice": invoice})
```

**DRF ViewSets (Vulnerable)**:
```python
# VULNERABLE: get_queryset returns ALL objects
class DocumentViewSet(viewsets.ModelViewSet):
    queryset = Document.objects.all()  # Any user can access any document
    serializer_class = DocumentSerializer

# SAFE: Scoped queryset
class DocumentViewSet(viewsets.ModelViewSet):
    serializer_class = DocumentSerializer

    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

**DRF Serializer Relations (Vulnerable)**:
```python
# VULNERABLE: User can set any owner_id
class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ['id', 'name', 'owner']  # owner is writable!
```

**Direct Model Access (Vulnerable)**:
```python
# VULNERABLE: No ownership verification
def update_profile(request, user_id):
    user = User.objects.get(pk=user_id)  # Any user_id accepted
    user.email = request.POST['email']
    user.save()
```

### Search Patterns

1. `grep` for: `get_object_or_404\\(` -- check for missing user/owner filter
2. `grep` for: `objects\\.get\\(pk=` or `objects\\.get\\(id=` -- check ownership
3. Check all `ModelViewSet` for `get_queryset` override with user scoping
4. `grep` for: `self\\.kwargs\\[` in DRF views -- trace to unscoped queries

### Severity Assessment

- **Critical**: Access to other users' sensitive data (PII, financial)
- **High**: Access to other users' content/resources
- **Medium**: Access to non-sensitive metadata
- **Low**: Informational with no security impact
"""
