/**
 * Integration Tests for @arcis/node
 *
 * These tests spin up real Express servers and make actual HTTP requests
 * to verify Arcis protections work correctly end-to-end.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import express, { Express, Request, Response, NextFunction } from 'express';
import { createServer, Server } from 'http';
import arcis, {
  createSanitizer,
  createRateLimiter,
  createHeaders,
  validate,
  errorHandler,
  createSafeLogger,
} from '../src/index';

// ============================================
// TEST UTILITIES
// ============================================

interface TestServer {
  app: Express;
  server: Server;
  url: string;
  close: () => Promise<void>;
}

async function createTestServer(setupRoutes: (app: Express) => void): Promise<TestServer> {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  setupRoutes(app);
  
  return new Promise((resolve) => {
    const server = createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as { port: number };
      const url = `http://127.0.0.1:${address.port}`;
      resolve({
        app,
        server,
        url,
        close: () => new Promise<void>((res) => server.close(() => res())),
      });
    });
  });
}

// ============================================
// FULL ARCIS MIDDLEWARE INTEGRATION
// ============================================

describe('Integration: Full Arcis Middleware', () => {
  let testServer: TestServer;
  let arcisMiddleware: ReturnType<typeof arcis>;

  beforeAll(async () => {
    arcisMiddleware = arcis({ rateLimit: { max: 100, windowMs: 60000 } });

    testServer = await createTestServer((app) => {
      app.use(...arcisMiddleware);
      
      app.post('/echo', (req: Request, res: Response) => {
        // Return the keys to show what's in the sanitized body
        res.json({ received: req.body, keys: Object.keys(req.body) });
      });
      
      app.get('/ping', (_req: Request, res: Response) => {
        res.json({ pong: true });
      });
    });
  });

  afterAll(async () => {
    (arcisMiddleware as any).close?.();
    await testServer.close();
  });

  it('should apply all security headers', async () => {
    const res = await fetch(`${testServer.url}/ping`);
    
    expect(res.headers.get('Content-Security-Policy')).toBeTruthy();
    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    expect(res.headers.get('X-XSS-Protection')).toBe('1; mode=block');
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
    expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(res.headers.get('X-Powered-By')).toBeNull();
  });

  it('should set rate limit headers', async () => {
    const res = await fetch(`${testServer.url}/ping`);
    
    expect(res.headers.get('X-RateLimit-Limit')).toBe('100');
    expect(res.headers.get('X-RateLimit-Remaining')).toBeTruthy();
    expect(res.headers.get('X-RateLimit-Reset')).toBeTruthy();
  });

  it('should sanitize XSS in request body', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: '<script>alert("xss")</script>' }),
    });
    
    const data = await res.json();
    expect(data.received.name).not.toContain('<script>');
    expect(data.received.name).toContain('&lt;');
  });

  it('should sanitize SQL injection in request body', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: "'; DROP TABLE users; --" }),
    });
    
    const data = await res.json();
    expect(data.received.query.toUpperCase()).not.toContain('DROP');
  });

  it('should block prototype pollution', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        __proto__: { admin: true },
        constructor: { prototype: { admin: true } },
        name: 'test' 
      }),
    });
    
    const data = await res.json();
    // Check that dangerous keys are NOT in the returned object's own keys
    expect(data.keys).not.toContain('__proto__');
    expect(data.keys).not.toContain('constructor');
    expect(data.keys).toContain('name');
    expect(data.received.name).toBe('test');
  });

  it('should block NoSQL injection operators', async () => {
    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        $gt: '',
        $where: 'function() { return true }',
        name: 'test' 
      }),
    });
    
    const data = await res.json();
    expect(data.received.$gt).toBeUndefined();
    expect(data.received.$where).toBeUndefined();
    expect(data.received.name).toBe('test');
  });
});

// ============================================
// SANITIZER INTEGRATION
// ============================================

describe('Integration: Sanitizer Middleware', () => {
  let testServer: TestServer;

  beforeAll(async () => {
    testServer = await createTestServer((app) => {
      app.use(createSanitizer());
      
      app.post('/body', (req: Request, res: Response) => {
        res.json({ body: req.body });
      });
      
      app.get('/query', (req: Request, res: Response) => {
        res.json({ query: req.query });
      });
      
      app.get('/params/:id', (req: Request, res: Response) => {
        res.json({ params: req.params });
      });
    });
  });

  afterAll(async () => {
    await testServer.close();
  });

  it('should sanitize body - XSS vectors', async () => {
    const vectors = [
      { input: '<script>alert(1)</script>', check: (s: string) => !s.includes('<script>') },
      { input: '<img onerror="alert(1)">', check: (s: string) => !s.includes('onerror') },
      { input: 'javascript:alert(1)', check: (s: string) => !s.toLowerCase().includes('javascript:') },
      { input: '<iframe src="evil.com">', check: (s: string) => !s.includes('<iframe') },
      { input: '<svg onload="alert(1)">', check: (s: string) => !s.includes('onload') },
      { input: 'data:text/html,<script>', check: (s: string) => !s.includes('data:') },
    ];

    for (const { input, check } of vectors) {
      const res = await fetch(`${testServer.url}/body`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: input }),
      });
      
      const data = await res.json();
      expect(check(data.body.value), `Failed for input: ${input}`).toBe(true);
    }
  });

  it('should sanitize body - SQL injection vectors', async () => {
    const vectors = [
      "'; DROP TABLE users; --",
      "1 OR 1=1",
      "SELECT * FROM users",
      "1; DELETE FROM users",
      "admin'--",
      "1 /* comment */ UNION SELECT",
    ];

    for (const input of vectors) {
      const res = await fetch(`${testServer.url}/body`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: input }),
      });
      
      const data = await res.json();
      const sanitized = data.body.query.toUpperCase();
      
      expect(sanitized).not.toContain('DROP');
      expect(sanitized).not.toContain('SELECT');
      expect(sanitized).not.toContain('DELETE');
      expect(sanitized).not.toContain('UNION');
    }
  });

  it('should sanitize body - path traversal vectors', async () => {
    const vectors = [
      '../../etc/passwd',
      '..\\..\\windows\\system32',
      '%2e%2e%2f%2e%2e%2f',
    ];

    for (const input of vectors) {
      const res = await fetch(`${testServer.url}/body`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: input }),
      });
      
      const data = await res.json();
      expect(data.body.path).not.toContain('../');
      expect(data.body.path).not.toContain('..\\');
    }
  });

  it('should sanitize query parameters', async () => {
    const res = await fetch(`${testServer.url}/query?search=${encodeURIComponent("<script>alert(1)</script>")}`);
    
    const data = await res.json();
    expect(data.query.search).not.toContain('<script>');
  });

  it('should handle nested objects', async () => {
    const res = await fetch(`${testServer.url}/body`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: {
          profile: {
            bio: '<script>xss</script>',
            links: ['<img onerror="evil()">', 'https://safe.com'],
          },
        },
      }),
    });
    
    const data = await res.json();
    expect(data.body.user.profile.bio).not.toContain('<script>');
    expect(data.body.user.profile.links[0]).not.toContain('onerror');
    expect(data.body.user.profile.links[1]).toContain('https://safe.com');
  });
});

// ============================================
// RATE LIMITER INTEGRATION
// ============================================

describe('Integration: Rate Limiter Middleware', () => {
  let testServer: TestServer;
  let rateLimiter: ReturnType<typeof createRateLimiter>;

  beforeAll(async () => {
    rateLimiter = createRateLimiter({ max: 5, windowMs: 60000 });
    
    testServer = await createTestServer((app) => {
      app.use(rateLimiter);
      
      app.get('/api', (_req: Request, res: Response) => {
        res.json({ ok: true });
      });
    });
  });

  afterAll(async () => {
    rateLimiter.close();
    await testServer.close();
  });

  it('should allow requests under the limit', async () => {
    for (let i = 0; i < 3; i++) {
      const res = await fetch(`${testServer.url}/api`);
      expect(res.status).toBe(200);
    }
  });

  it('should set correct rate limit headers', async () => {
    const res = await fetch(`${testServer.url}/api`);
    
    expect(res.headers.get('X-RateLimit-Limit')).toBe('5');
    expect(res.headers.get('X-RateLimit-Remaining')).toBeTruthy();
    expect(res.headers.get('X-RateLimit-Reset')).toBeTruthy();
  });

  it('should decrement remaining count', async () => {
    // Create a new server to have fresh rate limit state
    const freshRateLimiter = createRateLimiter({ max: 10, windowMs: 60000 });
    const freshServer = await createTestServer((app) => {
      app.use(freshRateLimiter);
      app.get('/test', (_req, res) => res.json({ ok: true }));
    });

    try {
      const res1 = await fetch(`${freshServer.url}/test`);
      const remaining1 = parseInt(res1.headers.get('X-RateLimit-Remaining') || '0', 10);
      
      const res2 = await fetch(`${freshServer.url}/test`);
      const remaining2 = parseInt(res2.headers.get('X-RateLimit-Remaining') || '0', 10);
      
      expect(remaining1).toBeGreaterThan(remaining2);
    } finally {
      freshRateLimiter.close();
      await freshServer.close();
    }
  });

  it('should block requests over the limit', async () => {
    const strictRateLimiter = createRateLimiter({ max: 2, windowMs: 60000 });
    const strictServer = await createTestServer((app) => {
      app.use(strictRateLimiter);
      app.get('/limited', (_req, res) => res.json({ ok: true }));
    });

    try {
      // First 2 requests should pass
      const res1 = await fetch(`${strictServer.url}/limited`);
      expect(res1.status).toBe(200);
      
      const res2 = await fetch(`${strictServer.url}/limited`);
      expect(res2.status).toBe(200);
      
      // Third request should be blocked
      const res3 = await fetch(`${strictServer.url}/limited`);
      expect(res3.status).toBe(429);
      
      const data = await res3.json();
      expect(data.error).toBeTruthy();
      expect(data.retryAfter).toBeDefined();
      expect(res3.headers.get('Retry-After')).toBeTruthy();
    } finally {
      strictRateLimiter.close();
      await strictServer.close();
    }
  });

  it('should respect skip function', async () => {
    const skipRateLimiter = createRateLimiter({ 
      max: 1, 
      windowMs: 60000,
      skip: (req) => req.path === '/health',
    });
    const skipServer = await createTestServer((app) => {
      app.use(skipRateLimiter);
      app.get('/health', (_req, res) => res.json({ healthy: true }));
      app.get('/api', (_req, res) => res.json({ ok: true }));
    });

    try {
      // Health check should always pass
      for (let i = 0; i < 5; i++) {
        const res = await fetch(`${skipServer.url}/health`);
        expect(res.status).toBe(200);
      }
      
      // But /api should still be rate limited
      await fetch(`${skipServer.url}/api`); // Use up limit
      const res = await fetch(`${skipServer.url}/api`);
      expect(res.status).toBe(429);
    } finally {
      skipRateLimiter.close();
      await skipServer.close();
    }
  });

  it('should use custom key generator', async () => {
    const customRateLimiter = createRateLimiter({ 
      max: 2, 
      windowMs: 60000,
      keyGenerator: (req) => req.headers['x-api-key'] as string || 'anonymous',
    });
    const customServer = await createTestServer((app) => {
      app.use(customRateLimiter);
      app.get('/api', (_req, res) => res.json({ ok: true }));
    });

    try {
      // User A makes 2 requests (uses up their limit)
      await fetch(`${customServer.url}/api`, { headers: { 'x-api-key': 'user-a' } });
      await fetch(`${customServer.url}/api`, { headers: { 'x-api-key': 'user-a' } });
      
      // User A is now blocked
      const resA = await fetch(`${customServer.url}/api`, { headers: { 'x-api-key': 'user-a' } });
      expect(resA.status).toBe(429);
      
      // But User B can still make requests
      const resB = await fetch(`${customServer.url}/api`, { headers: { 'x-api-key': 'user-b' } });
      expect(resB.status).toBe(200);
    } finally {
      customRateLimiter.close();
      await customServer.close();
    }
  });
});

// ============================================
// SECURITY HEADERS INTEGRATION
// ============================================

describe('Integration: Security Headers Middleware', () => {
  it('should set all default security headers', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders());
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    try {
      const res = await fetch(`${testServer.url}/`);
      
      // CSP
      const csp = res.headers.get('Content-Security-Policy');
      expect(csp).toBeTruthy();
      expect(csp).toContain("default-src 'self'");
      
      // XSS Protection
      expect(res.headers.get('X-XSS-Protection')).toBe('1; mode=block');
      
      // Content Type Options
      expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
      
      // Frame Options
      expect(res.headers.get('X-Frame-Options')).toBe('DENY');
      
      // HSTS
      const hsts = res.headers.get('Strict-Transport-Security');
      expect(hsts).toContain('max-age=');
      expect(hsts).toContain('includeSubDomains');
      
      // Referrer Policy
      expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
      
      // Permissions Policy
      expect(res.headers.get('Permissions-Policy')).toBeTruthy();
      
      // Cross-Domain Policy
      expect(res.headers.get('X-Permitted-Cross-Domain-Policies')).toBe('none');
      
      // Cache Control
      expect(res.headers.get('Cache-Control')).toContain('no-store');
      
      // Should NOT have X-Powered-By
      expect(res.headers.get('X-Powered-By')).toBeNull();
    } finally {
      await testServer.close();
    }
  });

  it('should allow custom CSP', async () => {
    const customCSP = "default-src 'none'; script-src 'self'";
    const testServer = await createTestServer((app) => {
      app.use(createHeaders({ contentSecurityPolicy: customCSP }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    try {
      const res = await fetch(`${testServer.url}/`);
      expect(res.headers.get('Content-Security-Policy')).toBe(customCSP);
    } finally {
      await testServer.close();
    }
  });

  it('should allow SAMEORIGIN frame options', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders({ frameOptions: 'SAMEORIGIN' }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    try {
      const res = await fetch(`${testServer.url}/`);
      expect(res.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    } finally {
      await testServer.close();
    }
  });

  it('should allow disabling specific headers', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders({ 
        contentSecurityPolicy: false as any,
        xssFilter: false,
        frameOptions: false,
      }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    try {
      const res = await fetch(`${testServer.url}/`);
      expect(res.headers.get('Content-Security-Policy')).toBeNull();
      expect(res.headers.get('X-XSS-Protection')).toBeNull();
      expect(res.headers.get('X-Frame-Options')).toBeNull();
      // Other headers should still be set
      expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    } finally {
      await testServer.close();
    }
  });

  it('should support custom HSTS configuration', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createHeaders({ 
        hsts: { maxAge: 86400, includeSubDomains: false, preload: true },
      }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    try {
      const res = await fetch(`${testServer.url}/`);
      const hsts = res.headers.get('Strict-Transport-Security');
      expect(hsts).toContain('max-age=86400');
      expect(hsts).not.toContain('includeSubDomains');
      expect(hsts).toContain('preload');
    } finally {
      await testServer.close();
    }
  });
});

// ============================================
// VALIDATOR INTEGRATION
// ============================================

describe('Integration: Validator Middleware', () => {
  let testServer: TestServer;

  beforeAll(async () => {
    testServer = await createTestServer((app) => {
      // User registration endpoint
      app.post('/users', 
        validate({
          email: { type: 'email', required: true },
          name: { type: 'string', min: 2, max: 50 },
          age: { type: 'number', min: 0, max: 150 },
          role: { type: 'string', enum: ['user', 'admin'] },
        }),
        (req: Request, res: Response) => {
          res.status(201).json({ user: req.body });
        }
      );
      
      // Query parameter validation
      app.get('/search',
        validate({ q: { type: 'string', required: true, min: 1 } }, 'query'),
        (req: Request, res: Response) => {
          res.json({ query: req.query });
        }
      );
      
      // Custom validation
      app.post('/custom',
        validate({
          password: { 
            type: 'string', 
            required: true,
            custom: (v) => (v as string).length >= 8 || 'Password must be at least 8 characters',
          },
        }),
        (req: Request, res: Response) => {
          res.json({ ok: true });
        }
      );
    });
  });

  afterAll(async () => {
    await testServer.close();
  });

  it('should validate required fields', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'John' }), // Missing email
    });
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors).toContain('email is required');
  });

  it('should validate email format', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'not-an-email' }),
    });
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors.some((e: string) => e.includes('valid email'))).toBe(true);
  });

  it('should validate string min/max length', async () => {
    // Too short
    const res1 = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'test@test.com', name: 'A' }),
    });
    
    expect(res1.status).toBe(400);
    const data1 = await res1.json();
    expect(data1.errors.some((e: string) => e.includes('at least 2'))).toBe(true);
    
    // Too long
    const res2 = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'test@test.com', name: 'A'.repeat(51) }),
    });
    
    expect(res2.status).toBe(400);
    const data2 = await res2.json();
    expect(data2.errors.some((e: string) => e.includes('at most 50'))).toBe(true);
  });

  it('should validate number range', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'test@test.com', age: -5 }),
    });
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors.some((e: string) => e.includes('at least 0'))).toBe(true);
  });

  it('should validate enum values', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'test@test.com', role: 'superadmin' }),
    });
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors.some((e: string) => e.includes('one of'))).toBe(true);
  });

  it('should prevent mass assignment', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email: 'test@test.com',
        isAdmin: true,       // Not in schema - should be stripped
        secretField: 'hack', // Not in schema - should be stripped
      }),
    });
    
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.user.email).toBe('test@test.com');
    expect(data.user.isAdmin).toBeUndefined();
    expect(data.user.secretField).toBeUndefined();
  });

  it('should validate query parameters', async () => {
    const res = await fetch(`${testServer.url}/search`);
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors.some((e: string) => e.includes('required'))).toBe(true);
  });

  it('should support custom validators', async () => {
    const res = await fetch(`${testServer.url}/custom`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: '1234' }), // Too short
    });
    
    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.errors.some((e: string) => e.includes('8 characters'))).toBe(true);
  });

  it('should pass valid data through', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email: 'john@example.com',
        name: 'John Doe',
        age: 25,
        role: 'user',
      }),
    });
    
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.user.email).toBe('john@example.com');
    expect(data.user.name).toBeDefined();
    expect(data.user.age).toBe(25);
    expect(data.user.role).toBe('user');
  });

  it('should sanitize validated string values', async () => {
    const res = await fetch(`${testServer.url}/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email: 'test@test.com',
        name: '<script>alert(1)</script>John',
      }),
    });
    
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.user.name).not.toContain('<script>');
  });
});

// ============================================
// ERROR HANDLER INTEGRATION
// ============================================

describe('Integration: Error Handler Middleware', () => {
  it('should hide error details in production mode', async () => {
    const testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Database connection failed at server 10.0.0.1');
      });
      app.use(errorHandler(false)); // Production mode
    });

    try {
      const res = await fetch(`${testServer.url}/error`);
      
      expect(res.status).toBe(500);
      const data = await res.json();
      expect(data.error).toBe('Internal Server Error');
      expect(data.stack).toBeUndefined();
      expect(data.details).toBeUndefined();
      expect(JSON.stringify(data)).not.toContain('10.0.0.1');
    } finally {
      await testServer.close();
    }
  });

  it('should show error details in development mode', async () => {
    const testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Something broke');
      });
      app.use(errorHandler(true)); // Dev mode
    });

    try {
      const res = await fetch(`${testServer.url}/error`);
      
      expect(res.status).toBe(500);
      const data = await res.json();
      expect(data.stack).toBeDefined();
      expect(data.details).toBe('Something broke');
    } finally {
      await testServer.close();
    }
  });

  it('should use custom status codes from errors', async () => {
    const testServer = await createTestServer((app) => {
      app.get('/not-found', () => {
        const error: any = new Error('Resource not found');
        error.statusCode = 404;
        throw error;
      });
      app.use(errorHandler(false));
    });

    try {
      const res = await fetch(`${testServer.url}/not-found`);
      
      expect(res.status).toBe(404);
      const data = await res.json();
      expect(data.error).toBe('Resource not found');
    } finally {
      await testServer.close();
    }
  });
});

// ============================================
// COMBINED SCENARIOS
// ============================================

describe('Integration: Combined Real-World Scenarios', () => {
  it('should protect a complete API endpoint', async () => {
    const rateLimiter = createRateLimiter({ max: 100, windowMs: 60000 });
    const testServer = await createTestServer((app) => {
      // Apply all protections
      app.use(createHeaders());
      app.use(rateLimiter);
      app.use(createSanitizer());
      
      // Protected endpoint
      app.post('/api/comments',
        validate({
          text: { type: 'string', required: true, min: 1, max: 1000 },
          authorId: { type: 'uuid' },
        }),
        (req: Request, res: Response) => {
          res.status(201).json({ comment: req.body });
        }
      );
      
      app.use(errorHandler(false));
    });

    try {
      // Test 1: Valid request with XSS in text (should be sanitized)
      const res1 = await fetch(`${testServer.url}/api/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          text: '<script>alert("xss")</script>Great post!',
          authorId: '123e4567-e89b-12d3-a456-426614174000',
        }),
      });
      
      expect(res1.status).toBe(201);
      const data1 = await res1.json();
      expect(data1.comment.text).not.toContain('<script>');
      expect(data1.comment.text).toContain('Great post!');
      
      // Verify headers are set
      expect(res1.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(res1.headers.get('X-RateLimit-Limit')).toBe('100');
      
      // Test 2: Invalid UUID format
      const res2 = await fetch(`${testServer.url}/api/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          text: 'Hello',
          authorId: 'not-a-uuid',
        }),
      });
      
      expect(res2.status).toBe(400);
      
      // Test 3: Mass assignment attempt
      const res3 = await fetch(`${testServer.url}/api/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          text: 'Normal comment',
          isApproved: true,  // Not in schema
          adminFlag: true,   // Not in schema
        }),
      });
      
      expect(res3.status).toBe(201);
      const data3 = await res3.json();
      expect(data3.comment.isApproved).toBeUndefined();
      expect(data3.comment.adminFlag).toBeUndefined();
    } finally {
      rateLimiter.close();
      await testServer.close();
    }
  });

  it('should handle form-urlencoded data', async () => {
    const testServer = await createTestServer((app) => {
      app.use(createSanitizer());
      
      app.post('/form', (req: Request, res: Response) => {
        res.json({ data: req.body });
      });
    });

    try {
      const res = await fetch(`${testServer.url}/form`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'name=<script>evil</script>&email=test@test.com',
      });
      
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.data.name).not.toContain('<script>');
    } finally {
      await testServer.close();
    }
  });
});
