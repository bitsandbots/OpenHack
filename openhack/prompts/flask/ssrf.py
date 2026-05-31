"""
Flask SSRF detection prompt.
"""

FLASK_SSRF_PROMPT = """## SSRF (Server-Side Request Forgery) in Flask

### What to Look For

1. **User-controlled URLs passed to requests/urllib/httpx**
2. **Webhook/callback URL injection**
3. **URL fetching in import, preview, or proxy features**

### Flask-Specific Patterns

**Requests Library (Vulnerable)**:
```python
# VULNERABLE: User controls URL
@app.route('/api/preview')
def preview():
    url = request.args.get('url')
    response = requests.get(url)  # SSRF!
    return jsonify({"content": response.text[:500]})

# VULNERABLE: Webhook callback
@app.route('/api/webhooks', methods=['POST'])
@login_required
def create_webhook():
    url = request.json['callback_url']
    Webhook.create(url=url, user_id=current_user.id)
    # Later: requests.post(webhook.url, json=event) -- hits internal services
```

**urllib (Vulnerable)**:
```python
# VULNERABLE: urlopen with user URL
from urllib.request import urlopen
@app.route('/api/import')
def import_data():
    url = request.form['source']
    data = urlopen(url).read()  # file://, http://169.254.169.254, etc.
    return process(data)
```

**httpx / aiohttp (Vulnerable)**:
```python
# VULNERABLE: async HTTP client with user URL
import httpx
async with httpx.AsyncClient() as client:
    r = await client.get(request.json['url'])
```

### Search Patterns

1. `grep` for: `requests\\.get\\(`, `requests\\.post\\(`, `requests\\.head\\(`
2. `grep` for: `urlopen\\(`, `urllib\\.request`
3. `grep` for: `httpx`, `aiohttp`
4. Trace whether the URL argument originates from `request.args`, `request.form`, `request.json`

### Severity Assessment

- **High**: SSRF reaching internal services or cloud metadata
- **High**: SSRF with response body returned to attacker
- **Medium**: Blind SSRF (request sent, no response returned)
- **Low**: SSRF limited to specific protocols/hosts by validation
"""
