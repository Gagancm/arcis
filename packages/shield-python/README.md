# Shield Python 🛡️

**One-line security for Python web applications.**

Shield is a cross-platform security library that provides drop-in protection against common web vulnerabilities. Part of the Shield ecosystem with implementations for Node.js, Python, Go, Java, and C#.

## Installation

```bash
# Core library (no dependencies)
pip install shield-security

# With framework integrations
pip install shield-security[flask]
pip install shield-security[fastapi]
pip install shield-security[django]

# All frameworks + dev tools
pip install shield-security[dev]
```

## Quick Start

### Flask

```python
from flask import Flask
from shield import Shield

app = Flask(__name__)
Shield(app)  # That's it! Your app is now protected.

@app.route('/')
def hello():
    return 'Hello, World!'
```

### FastAPI

```python
from fastapi import FastAPI
from shield.fastapi import ShieldMiddleware

app = FastAPI()
app.add_middleware(ShieldMiddleware)

@app.get('/')
async def hello():
    return {'message': 'Hello, World!'}
```

### Django

```python
# settings.py
MIDDLEWARE = [
    'shield.django.ShieldMiddleware',
    # ... other middleware
]

# Optional configuration
SHIELD_CONFIG = {
    'rate_limit_max': 100,
    'rate_limit_window_ms': 60000,
    'sanitize_xss': True,
    'sanitize_sql': True,
}
```

## Features

### 🧹 Input Sanitization
Automatically sanitize user input to prevent:
- **XSS** (Cross-Site Scripting)
- **SQL Injection**
- **NoSQL Injection** (MongoDB operators)
- **Path Traversal** (`../` attacks)
- **Prototype Pollution** (`__proto__`, `constructor`)

```python
from shield import sanitize_string, sanitize_dict

# Sanitize a string
clean = sanitize_string("<script>alert('xss')</script>")
# Result: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

# Sanitize a dictionary (including nested objects)
data = {"name": "<script>xss</script>", "$gt": ""}
clean = sanitize_dict(data)
# Result: {"name": "&lt;script&gt;..."}  ($gt key removed)
```

### 🚦 Rate Limiting
Protect against brute force and DDoS attacks:

```python
from shield import RateLimiter

limiter = RateLimiter(
    max_requests=100,      # 100 requests
    window_ms=60000,       # per minute
)

# In your route handler
try:
    limiter.check(request)
except RateLimitExceeded as e:
    return {"error": e.message}, 429
```

### 🔒 Security Headers
Automatically add security headers to all responses:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security`
- `X-XSS-Protection: 1; mode=block`

### ✅ Input Validation

```python
from shield import Validator, validate_email, validate_url

# Quick validation
if validate_email(user_input):
    print("Valid email!")

# Full validator
assert Validator.email("test@example.com")  # True
assert Validator.url("https://example.com")  # True
assert Validator.uuid("550e8400-e29b-41d4-a716-446655440000")  # True
assert Validator.length("hello", min_len=3, max_len=10)  # True
```

### 📝 Safe Logging
Log safely without exposing secrets:

```python
from shield import SafeLogger

logger = SafeLogger()

# Automatically redacts sensitive fields
logger.info("User login", {"email": "user@test.com", "password": "secret"})
# Output: {"email": "user@test.com", "password": "[REDACTED]"}

# Prevents log injection (removes newlines/control characters)
logger.info("User: attacker\nAdmin: true")  # Newlines stripped
```

## Configuration

All frameworks support the same configuration options:

```python
# Flask
Shield(
    app,
    sanitize=True,
    sanitize_xss=True,
    sanitize_sql=True,
    sanitize_nosql=True,
    sanitize_path=True,
    rate_limit=True,
    rate_limit_max=100,
    rate_limit_window_ms=60000,
    headers=True,
    csp="default-src 'self'",
)

# FastAPI
app.add_middleware(
    ShieldMiddleware,
    rate_limit_max=50,
    sanitize_sql=False,
)

# Django (settings.py)
SHIELD_CONFIG = {
    'rate_limit_max': 50,
    'sanitize_sql': False,
}
```

## Standalone Middleware (Django)

Use individual components if you only need specific protection:

```python
MIDDLEWARE = [
    'shield.django.ShieldSanitizeMiddleware',   # Only sanitization
    'shield.django.ShieldRateLimitMiddleware',  # Only rate limiting
    'shield.django.ShieldHeadersMiddleware',    # Only security headers
]
```

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=shield --cov-report=html
```

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `Shield` | Main class - configures all protections |
| `Sanitizer` | Input sanitization |
| `RateLimiter` | Rate limiting |
| `SecurityHeaders` | Security headers |
| `Validator` | Input validation |
| `SafeLogger` | Safe logging with redaction |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `RateLimitExceeded` | Raised when rate limit is exceeded |
| `ValidationError` | Raised when validation fails |

### Convenience Functions

| Function | Description |
|----------|-------------|
| `sanitize_string(value)` | Sanitize a single string |
| `sanitize_dict(data)` | Sanitize a dictionary |
| `sanitize_xss(value)` | XSS sanitization only |
| `sanitize_sql(value)` | SQL injection sanitization only |
| `sanitize_nosql(data)` | NoSQL injection sanitization only |
| `sanitize_path(value)` | Path traversal sanitization only |
| `validate_email(value)` | Validate email format |
| `validate_url(value)` | Validate URL format |
| `validate_uuid(value)` | Validate UUID format |

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests to the main Shield repository.
