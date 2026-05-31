"""
Django SSRF detection prompt.
"""

DJANGO_SSRF_PROMPT = """## SSRF (Server-Side Request Forgery) in Django

### What to Look For

1. **User-controlled URLs passed to HTTP clients**
2. **Webhook/callback URL injection**
3. **URL fetching in import/export features**
4. **Image/file download from user-provided URLs**

### Django-Specific Patterns

**Direct URL Fetching (Vulnerable)**:
```python
# VULNERABLE: User controls the URL
import requests

def fetch_preview(request):
    url = request.GET['url']
    response = requests.get(url)  # SSRF! Can hit internal services
    return HttpResponse(response.text)

# VULNERABLE: Webhook registration with no URL validation
def register_webhook(request):
    url = request.POST['callback_url']
    Webhook.objects.create(url=url, user=request.user)
    # Later: requests.post(webhook.url, data=event_data)
```

**urllib Usage (Vulnerable)**:
```python
# VULNERABLE: urllib with user URL
from urllib.request import urlopen
def import_data(request):
    url = request.POST['source_url']
    data = urlopen(url).read()  # Can access file://, http://169.254.169.254, etc.
```

**Image/Avatar Download (Vulnerable)**:
```python
# VULNERABLE: Downloading from user-provided URL
def set_avatar(request):
    image_url = request.POST['avatar_url']
    response = requests.get(image_url)  # SSRF via avatar
    save_image(response.content)
```

### Search Patterns

1. `grep` for: `requests\\.get\\(`, `requests\\.post\\(`, `requests\\.head\\(`
2. `grep` for: `urlopen\\(`, `urllib\\.request`
3. `grep` for: `httpx`, `aiohttp\\.ClientSession`
4. Trace whether the URL argument comes from user input (request.GET/POST/body)

### Severity Assessment

- **High**: SSRF reaching internal services or cloud metadata
- **High**: SSRF with response body returned to attacker
- **Medium**: Blind SSRF (no response returned)
- **Low**: SSRF limited to specific protocols/hosts
"""
