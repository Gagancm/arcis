# Shield

**Cross-platform security middleware for web applications**

Shield provides comprehensive protection against common web vulnerabilities with a consistent API across Node.js, Python, and Go. One line of code enables XSS prevention, SQL injection protection, rate limiting, security headers, and more.

---

## Installation

**Node.js / TypeScript**
```bash
npm install @shield/node
```

**Python**
```bash
pip install shield-security
```

**Go**
```bash
go get github.com/aspect.dev/shield-go
```

---

## Quick Start

### Node.js / Express

```javascript
import shield from '@shield/node';

const app = express();
app.use(shield());

// That's it. Your app now has:
// - XSS sanitization on all inputs
// - SQL/NoSQL injection protection
// - Rate limiting (100 req/min per IP)
// - Security headers (CSP, HSTS, X-Frame-Options, etc.)
```

### Python / Flask

```python
from shield import Shield

app = Flask(__name__)
Shield(app)
```

### Python / FastAPI

```python
from shield.fastapi import ShieldMiddleware

app = FastAPI()
app.add_middleware(ShieldMiddleware)
```

### Python / Django

```python
# settings.py
MIDDLEWARE = [
    'shield.django.ShieldMiddleware',
    # ... other middleware
]
```

### Go / net/http

```go
import shield "github.com/aspect.dev/shield-go"

func main() {
    http.Handle("/", shield.Protect(myHandler))
    http.ListenAndServe(":8080", nil)
}
```

### Go / Gin

```go
import shieldgin "github.com/aspect.dev/shield-go/gin"

func main() {
    r := gin.Default()
    r.Use(shieldgin.Middleware())
    r.Run()
}
```

### Go / Echo

```go
import shieldecho "github.com/aspect.dev/shield-go/echo"

func main() {
    e := echo.New()
    e.Use(shieldecho.Middleware())
    e.Start(":8080")
}
```

---

## Features

| Feature | Description |
|---------|-------------|
| **XSS Prevention** | Sanitizes script tags, event handlers, javascript: URLs, and encodes HTML entities |
| **SQL Injection Protection** | Removes dangerous SQL keywords and comment sequences |
| **NoSQL Injection Protection** | Blocks MongoDB operators ($gt, $where, etc.) in request data |
| **Path Traversal Protection** | Sanitizes ../ sequences and encoded variants |
| **Prototype Pollution Prevention** | Blocks __proto__, constructor, and prototype keys |
| **Rate Limiting** | Configurable request limits per IP with automatic cleanup |
| **Security Headers** | Sets CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more |
| **Input Validation** | Schema-based validation with type checking and constraints |
| **Safe Logging** | Automatic redaction of passwords, tokens, and sensitive data |
| **Error Handling** | Production-safe error responses that hide internal details |

---

## Configuration

All SDKs support the same configuration options:

```javascript
// Node.js
app.use(shield({
  sanitize: true,           // Enable input sanitization
  rateLimit: {
    max: 100,               // Max requests per window
    windowMs: 60000,        // Window size (1 minute)
  },
  headers: {
    contentSecurityPolicy: "default-src 'self'",
    frameOptions: 'DENY',
  },
}));
```

```python
# Python
Shield(app,
    sanitize=True,
    rate_limit_max=100,
    rate_limit_window_ms=60000,
    csp="default-src 'self'",
)
```

```go
// Go
shield.MiddlewareWithConfig(shield.Config{
    Sanitize:        true,
    RateLimitMax:    100,
    RateLimitWindow: time.Minute,
    CSP:             "default-src 'self'",
})
```

---

## Granular Control

Use individual middleware for fine-grained control:

### Node.js

```javascript
import { createSanitizer, createRateLimiter, createHeaders, validate } from '@shield/node';

// Apply individually
app.use(createHeaders());
app.use(createRateLimiter({ max: 100 }));
app.use(createSanitizer());

// Validate specific routes
app.post('/users', validate({
  email: { type: 'email', required: true },
  age: { type: 'number', min: 0, max: 150 },
}), handler);
```

### Python

```python
from shield.core import Sanitizer, RateLimiter, SecurityHeaders, SchemaValidator

# Use components directly
sanitizer = Sanitizer()
clean_data = sanitizer.sanitize_dict(user_input)

# Schema validation
validator = SchemaValidator({
    'email': {'type': 'email', 'required': True},
    'age': {'type': 'number', 'min': 0, 'max': 150},
})
validated, errors = validator.validate(data)
```

### Go

```go
import shield "github.com/aspect.dev/shield-go"

// Use components directly
sanitizer := shield.NewSanitizer()
clean := sanitizer.SanitizeString(userInput)

// Validate
validator := shield.NewValidator()
if !validator.Email(email) {
    // handle invalid email
}
```

---

## Security Headers

Shield sets the following headers by default:

| Header | Default Value |
|--------|---------------|
| Content-Security-Policy | `default-src 'self'; script-src 'self'; ...` |
| X-Content-Type-Options | `nosniff` |
| X-Frame-Options | `DENY` |
| X-XSS-Protection | `1; mode=block` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `geolocation=(), microphone=(), camera=()` |

Headers that are removed:
- `X-Powered-By`
- `Server`

---

## Rate Limiting

Rate limit responses include standard headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 60
```

When exceeded, returns HTTP 429 with:

```json
{
  "error": "Too many requests, please try again later.",
  "retryAfter": 45
}
```

### Custom Store (Redis)

```javascript
// Node.js - see examples/redis-store/
import { createRateLimiter } from '@shield/node';

app.use(createRateLimiter({
  max: 100,
  store: new RedisStore(redisClient),
}));
```

---

## Project Structure

```
shield/
├── spec/
│   ├── API_SPEC.md              # API specification
│   └── TEST_VECTORS.json        # Cross-platform test cases
├── packages/
│   ├── core/
│   │   └── patterns.json        # Shared security patterns
│   ├── shield-node/             # Node.js SDK
│   ├── shield-python/           # Python SDK
│   └── shield-go/               # Go SDK
├── examples/
│   └── redis-store/             # Redis store examples
└── docs/
    └── code-structure.md        # Architecture documentation
```

### Contract-First Design

Shield follows a contract-first approach:

1. **`spec/API_SPEC.md`** defines the behavior all SDKs must implement
2. **`spec/TEST_VECTORS.json`** provides test cases all SDKs must pass
3. **`packages/core/patterns.json`** contains shared security patterns

This ensures consistent behavior across all languages.

---

## SDK Status

| SDK | Status | Package Manager | Frameworks |
|-----|--------|-----------------|------------|
| Node.js | ✅ Stable | npm | Express, Fastify, Koa |
| Python | ✅ Stable | PyPI | Flask, FastAPI, Django |
| Go | ✅ Stable | Go modules | net/http, Gin, Echo |
| Java | 🔨 In Development | Maven | Spring Boot |
| C# | 🔨 In Development | NuGet | ASP.NET Core |

---

## Development

### Running Tests

```bash
# Node.js
cd packages/shield-node
npm test

# Python
cd packages/shield-python
pytest

# Go
cd packages/shield-go
go test ./...
```

### Building

```bash
# Node.js
npm run build

# Python
pip install -e .

# Go
go build ./...
```

---

## Cleanup

Shield uses background threads for rate limit cleanup. Call `close()` when shutting down:

```javascript
// Node.js
const middleware = shield();
process.on('SIGTERM', () => middleware.close());
```

```python
# Python
shield_instance = Shield(app)
atexit.register(shield_instance.close)
```

```go
// Go
defer shield.Cleanup()
```

---

## Contributing

Contributions are welcome. Please ensure:

1. All changes pass existing tests
2. New features include tests aligned with `spec/TEST_VECTORS.json`
3. Code follows the existing style conventions

---

## License

MIT
