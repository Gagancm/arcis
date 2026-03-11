# Arcis

Cross-platform security middleware for Node.js, Python, and Go.

One line of code. XSS, SQL injection, NoSQL injection, path traversal, command injection, rate limiting, security headers, schema validation, and safe logging — handled.

## Install

```bash
npm install @arcis/node          # Node.js
pip install arcis                # Python
go get github.com/GagancM/arcis  # Go
```

## Quick Start

```js
// Express
app.use(arcis());
```

```python
# Flask
Arcis(app)

# FastAPI
app.add_middleware(ArcisMiddleware)

# Django — add to MIDDLEWARE in settings.py
'arcis.django.ArcisMiddleware'
```

```go
// Gin
r.Use(arcisgin.Middleware())

// Echo
e.Use(arcisecho.Middleware())
```

That's it. Sanitization, rate limiting, and security headers are on.

## What It Does

- **Input sanitization** — XSS, SQL injection, NoSQL injection, path traversal, command injection
- **Rate limiting** — per-IP, in-memory or Redis, with `X-RateLimit-*` headers
- **Security headers** — CSP, HSTS, X-Frame-Options, and more out of the box
- **Schema validation** — type checking, ranges, enums, mass assignment prevention
- **Safe logging** — sensitive key redaction, log injection prevention
- **Error handling** — production-safe error responses (no stack traces leaked)

## Supported Frameworks

| SDK | Frameworks | Status |
|-----|------------|--------|
| Node.js | Express | Stable |
| Python | Flask, FastAPI, Django | Stable |
| Go | net/http, Gin, Echo | Stable |
| Java | Spring Boot | Planned |
| C# | ASP.NET Core | Planned |

## How It Works

All SDKs load security patterns from a shared `patterns.json` at runtime. A shared spec (`API_SPEC.md`) and test vectors (`TEST_VECTORS.json`) enforce identical behavior across languages.

## Documentation

Detailed configuration, API reference, Redis setup, granular middleware usage, and architecture docs are in the [`docs/`](docs/) directory.

## Contributing

1. All changes must pass existing tests
2. New features require test cases aligned with `spec/TEST_VECTORS.json`
3. Pattern changes in `packages/core/patterns.json` must be reflected in all SDKs

## License

MIT
