"""
Django authentication/authorization bypass detection prompt.
"""

DJANGO_AUTH_BYPASS_PROMPT = """## Authentication/Authorization Bypass in Django

### What to Look For

1. **Missing @login_required or permission decorators**
2. **DRF views with AllowAny or no permission_classes**
3. **Broken has_permission / has_object_permission**
4. **Unprotected admin or management views**

### Django-Specific Patterns

**Function-Based Views (Vulnerable)**:
```python
# VULNERABLE: No auth decorator
def delete_account(request):
    User.objects.filter(id=request.POST['user_id']).delete()
    return JsonResponse({"ok": True})

# SAFE: Auth required
@login_required
@permission_required('accounts.delete_user')
def delete_account(request):
    ...
```

**DRF ViewSets (Vulnerable)**:
```python
# VULNERABLE: AllowAny on sensitive endpoint
class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]  # Anyone can CRUD users!
    queryset = User.objects.all()
    serializer_class = UserSerializer

# VULNERABLE: No permission_classes (DRF default may be AllowAny)
class PaymentViewSet(viewsets.ModelViewSet):
    queryset = Payment.objects.all()
    # permission_classes not set -- uses DEFAULT_PERMISSION_CLASSES
```

**Class-Based Views (Vulnerable)**:
```python
# VULNERABLE: Missing LoginRequiredMixin
class AdminDashboard(TemplateView):
    template_name = "admin/dashboard.html"

    def get_context_data(self, **kwargs):
        return {"users": User.objects.all()}  # Exposed without auth
```

**Broken Object Permissions**:
```python
# VULNERABLE: has_permission passes but has_object_permission is never called
class DocumentViewSet(viewsets.ModelViewSet):
    def get_object(self):
        return Document.objects.get(pk=self.kwargs['pk'])
        # check_object_permissions() never called!
```

### Search Patterns

1. `grep` for: `def get\\(`, `def post\\(`, `def delete\\(` in views without `@login_required`
2. `grep` for: `AllowAny`, `permission_classes`
3. `grep` for: `ModelViewSet`, `ViewSet`, `APIView` -- check each for permission_classes
4. Check `settings.py` for `DEFAULT_PERMISSION_CLASSES`

### Severity Assessment

- **Critical**: Admin or management functionality without auth
- **High**: User data modification without proper auth
- **Medium**: Read access to non-sensitive data without auth
- **Low**: Informational endpoints exposed
"""
