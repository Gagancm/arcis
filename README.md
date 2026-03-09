# Shield

**Cross-platform security middleware for Node.js, Python, and Go**

Shield protects web applications against common vulnerabilities — XSS, SQL injection, NoSQL injection, path traversal, and more — with a single line of code and a consistent API across all supported languages.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Features](#features)
- [Configuration](#configuration)
- [Rate Limiting](#rate-limiting)
- [Security Headers](#security-headers)
- [Input Sanitization](#input-sanitization)
- [Schema Validation](#schema-validation)
- [Distributed Rate Limiting (Redis)](#distributed-rate-limiting-redis)
- [Granular Middleware](#granular-middleware)
- [Resource Cleanup](#resource-cleanup)
- [Project Structure](#project-structure)
- [SDK Status](#sdk-status)
- [Development](#development)
- [License](#license)

---

## Installation

**Node.js / TypeScript**
```bash
npm install @shield/node
```

**Python**
```bash
pip install shield-security

# With Redis support
pip install shield-security[redis]
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
import express from 'express';

const app = express();
app.use(shield());

app.listen(3000);
```

### Python / Flask

```python
from flask import Flask
from shield import Shield

app = Flask(__name__)
Shield(app)
```

### Python / FastAPI

```python
from fastapi import FastAPI
from shield.fastapi import ShieldMiddleware

app = FastAPI()
app.add_middleware(ShieldMiddleware)
```

### Python / Django

```python
# settings.py
MIDDLEWARE = [
    'shield.django.ShieldMiddleware',
    # ...
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
import (
    "github.com/gin-gonic/gin"
    shieldgin "github.com/aspect.dev/shield-go/gin"
)

func main() {
    r := gin.Default()
    r.Use(shieldgin.Middleware())
    r.Run(":8080")
}
```

### Go / Echo

```go
import (
    "github.com/labstack/echo/v4"
    shieldecho "github.com/aspect.dev/shield-go/echo"
)

func main() {
    e := echo.New()
    e.Use(shieldecho.Middleware())
    e.Start(":8080")
}
```

---

## Features

| Feature | Node.js | Python | Go |
|---------|:-------:|:------:|:--:|
| XSS sanitization | ✅ | ✅ | ✅ |
| SQL injection protection | ✅ | ✅ | ✅ |
| NoSQL injection protection | ✅ | ✅ | ✅ |
| Path traversal protection | ✅ | ✅ | ✅ |
| Command injection protection | ✅ | ✅ | ✅ |
| Prototype pollution prevention | ✅ | — | — |
| Rate limiting (in-memory) | ✅ | ✅ | ✅ |
| Rate limiting (Redis) | ✅ | ✅ | ✅ |
| Security headers | ✅ | ✅ | ✅ |
| Schema validation | ✅ | ✅ | ✅ |
| Safe logging | ✅ | ✅ | — |
| Production error handling | ✅ | ✅ | ✅ |

---

## Configuration

All SDKs share the same configuration surface.

### Node.js

```javascript
app.use(shield({
  sanitize: true,
  rateLimit: {
    max: 100,
    windowMs: 60_000,
  },
  headers: {
    contentSecurityPolicy: "default-src 'self'",
    frameOptions: 'DENY',
    cacheControl: true,           // boolean or custom string
  },
}));
```

### Python

```python
Shield(app,
    sanitize=True,
    rate_limit_max=100,
    rate_limit_window_ms=60_000,
    csp="default-src 'self'",
    cache_control=True,           # True for secure default, or a custom string
)
```

### Go

```go
// net/http
shield.NewWithConfig(shield.Config{
    Sanitize:          true,
    RateLimitMax:      100,
    RateLimitWindow:   time.Minute,
    CSP:               "default-src 'self'",
    CacheControl:      true,
    CacheControlValue: "",        // Empty = use secure default
})

// Gin
r.Use(shieldgin.MiddlewareWithConfig(shieldgin.Config{
    RateLimitMax:    100,
    RateLimitWindow: time.Minute,
    CSP:             "default-src 'self'",
}))
```

---

## Rate Limiting

Rate-limited responses include standard headers:

```
X-RateLimit-Limit:     100
X-RateLimit-Remaining: 95
X-RateLimit-Reset:     42
```

When a client exceeds the limit, Shield returns HTTP `429`:

```json
{
  "error": "Too many requests, please try again later.",
  "retryAfter": 42
}
```

The window resets automatically. No configuration required beyond `max` and `windowMs`.

---

## Security Headers

Shield sets the following response headers by default:

| Header | Default Value |
|--------|---------------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Cache-Control` | `no-store, no-cache, must-revalidate, proxy-revalidate` |
| `X-Permitted-Cross-Domain-Policies` | `none` |

Headers removed from responses:
- `Server`
- `X-Powered-By`

### Custom Cache-Control

```python
# Python — pass a string instead of True
Shield(app, cache_control="public, max-age=3600")
```

```javascript
// Node.js
app.use(shield({ headers: { cacheControl: "public, max-age=3600" } }));
```

```go
// Go
shield.Config{
    CacheControl:      true,
    CacheControlValue: "public, max-age=3600",
}
```

---

## Input Sanitization

Sanitization runs on all string values in the request body recursively. You can also call the sanitizer directly:

### Node.js

```javascript
import { createSanitizer } from '@shield/node';

const sanitizer = createSanitizer();
const clean = sanitizer.sanitizeString(userInput);
const cleanObj = sanitizer.sanitizeObject(requestBody);
```

### Python

```python
from shield.core import Sanitizer

sanitizer = Sanitizer()
clean = sanitizer.sanitize_string(user_input)
clean_obj = sanitizer.sanitize_dict(request_body)
```

### Go

```go
sanitizer := shield.NewSanitizer(shield.DefaultConfig())
clean := sanitizer.SanitizeString(userInput)
cleanMap := sanitizer.SanitizeMap(requestBody)
```

---

## Schema Validation

### Node.js

```javascript
import { validate } from '@shield/node';

app.post('/users', validate({
  email:    { type: 'email',  required: true },
  age:      { type: 'number', min: 0, max: 150 },
  username: { type: 'string', minLength: 3, maxLength: 32 },
}), handler);
```

### Python

```python
from shield.core import SchemaValidator

validator = SchemaValidator({
    'email':    {'type': 'email',  'required': True},
    'age':      {'type': 'number', 'min': 0, 'max': 150},
    'username': {'type': 'string', 'min_length': 3, 'max_length': 32},
})
validated, errors = validator.validate(request_data)
if errors:
    return error_response(errors)
```

### Go

```go
validator := shield.NewValidator(shield.ValidationSchema{
    "email": {Type: "email", Required: true},
    "age":   {Type: "number", Min: 0, Max: 150},
})
validated, err := validator.Validate(data)
```

---

## Distributed Rate Limiting (Redis)

For multi-instance deployments, plug in a Redis-backed store instead of the default in-memory store.

### Node.js

```javascript
import { createRateLimiter } from '@shield/node';
import { RedisStore } from './stores/redis';

app.use(createRateLimiter({
  max: 100,
  windowMs: 60_000,
  store: new RedisStore(redisClient),
}));
```

### Python / Flask (sync)

```python
from shield import Shield
from shield.stores.redis import RedisRateLimitStore
import redis

client = redis.Redis(host='localhost', port=6379, db=0)
store = RedisRateLimitStore(client)

Shield(app, rate_limit_store=store)
```

### Python / FastAPI (async)

```python
from shield.fastapi import ShieldMiddleware
from shield.stores.redis import AsyncRedisRateLimitStore
import redis.asyncio as aioredis

client = aioredis.Redis(host='localhost', port=6379, db=0)
store = AsyncRedisRateLimitStore(client)

app.add_middleware(ShieldMiddleware, rate_limit_store=store)
```

Install the Redis extra:
```bash
pip install shield-security[redis]
```

### Go / net/http

```go
import shield "github.com/aspect.dev/shield-go"

store := myredis.NewStore(redisClient) // implements shield.RateLimitStore
limiter := shield.NewRateLimiterWithStore(100, time.Minute, store)
```

### Go / Gin

```go
import shieldgin "github.com/aspect.dev/shield-go/gin"

r.Use(shieldgin.RateLimitWithStore(100, time.Minute, store))
```

### Go / Echo

```go
import shieldecho "github.com/aspect.dev/shield-go/echo"

e.Use(shieldecho.RateLimitWithStore(100, time.Minute, store))
```

The `RateLimitStore` interface (Go):

```go
type RateLimitStore interface {
    Get(key string) *RateLimitEntry
    Set(key string, entry *RateLimitEntry)
    Increment(key string) int
    Cleanup()
}
```

---

## Granular Middleware

Apply protections individually instead of using the combined `shield()` middleware.

### Node.js

```javascript
import { createSanitizer, createRateLimiter, createHeaders } from '@shield/node';

app.use(createHeaders());
app.use(createRateLimiter({ max: 200, windowMs: 60_000 }));
app.use(createSanitizer());
```

### Python

```python
from shield.core import Sanitizer, RateLimiter, SecurityHeaders

app.before_request(SecurityHeaders().apply)
limiter = RateLimiter(max_requests=200, window_ms=60_000)
```

### Go / Gin

```go
r.Use(shieldgin.Headers())
r.Use(shieldgin.RateLimit(200, time.Minute))
r.Use(shieldgin.Sanitizer())
```

### Go / Echo

```go
e.Use(shieldecho.Headers())
e.Use(shieldecho.RateLimit(200, time.Minute))
e.Use(shieldecho.Sanitizer())
```

---

## Resource Cleanup

Shield runs a background goroutine (Go) or thread (Python) for periodic cleanup of expired rate-limit entries. Stop it on shutdown to avoid resource leaks.

### Node.js

```javascript
const middleware = shield();
process.on('SIGTERM', () => middleware.close());
```

### Python

```python
import atexit
shield_instance = Shield(app)
atexit.register(shield_instance.close)
```

### Go — graceful shutdown

```go
ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

go r.Run(":8080")

<-ctx.Done()
shieldgin.Cleanup()
```

```go
// Or simply:
defer shieldgin.Cleanup()
```

---

## Project Structure

```
shield/
├── spec/
│   ├── API_SPEC.md              # Behaviour contract all SDKs must implement
│   └── TEST_VECTORS.json        # Shared test cases for cross-platform parity
├── packages/
│   ├── core/
│   │   └── patterns.json        # Shared regex patterns for security rules
│   ├── shield-node/             # Node.js / TypeScript SDK
│   ├── shield-python/           # Python SDK
│   │   └── shield/stores/       # Pluggable store implementations (Redis, etc.)
│   └── shield-go/               # Go SDK
│       ├── gin/                 # Gin adapter
│       └── echo/                # Echo adapter
├── examples/
│   └── redis-store/             # Redis store integration examples
└── docs/
    └── code-structure.md        # Architecture and design decisions
```

### Contract-First Design

1. **`spec/API_SPEC.md`** — defines the behaviour every SDK must implement
2. **`spec/TEST_VECTORS.json`** — test inputs and expected outputs shared across all languages
3. **`packages/core/patterns.json`** — regex patterns loaded by each SDK at runtime

This ensures identical sanitization results regardless of language.

---

## SDK Status

| SDK | Status | Install | Frameworks |
|-----|--------|---------|------------|
| Node.js | ✅ Stable | `npm install @shield/node` | Express, Fastify, Koa |
| Python | ✅ Stable | `pip install shield-security` | Flask, FastAPI, Django |
| Go | ✅ Stable | `go get github.com/aspect.dev/shield-go` | net/http, Gin, Echo |
| Java | 🔨 Planned | Maven | Spring Boot |
| C# | 🔨 Planned | NuGet | ASP.NET Core |

---

## Development

### Running Tests

```bash
# Node.js
cd packages/shield-node && npm test

# Python
cd packages/shield-python && pytest

# Python benchmarks
cd packages/shield-python && pytest tests/test_benchmarks.py --benchmark-only

# Go
cd packages/shield-go && go test ./...
```

### Building

```bash
# Node.js
cd packages/shield-node && npm run build

# Python
cd packages/shield-python && pip install -e .

# Go
cd packages/shield-go && go build ./...
```

### Contributing

1. All changes must pass existing tests
2. New features require test cases aligned with `spec/TEST_VECTORS.json`
3. Cross-platform behaviour must be consistent — if you change a pattern in `packages/core/patterns.json`, update all three SDKs

---

## License

MIT
