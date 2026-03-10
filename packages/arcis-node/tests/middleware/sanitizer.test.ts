/**
 * Sanitizer Middleware Tests
 * Tests for src/middleware (sanitize functionality via createSanitizer)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import { createSanitizer } from '../../src/sanitizers/sanitize';
import { mockRequest, mockResponse, mockNext, createTestServer } from '../setup';

describe('createSanitizer middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Body Sanitization', () => {
    it('should sanitize XSS in req.body', () => {
      const req = mockRequest({ body: { name: '<script>xss</script>' } });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      sanitizer(req as Request, res as Response, mockNext);

      expect((req.body as { name: string }).name).not.toContain('<script>');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should sanitize SQL injection in req.body (sanitize mode)', () => {
      const req = mockRequest({ body: { query: "'; DROP TABLE users;--" } });
      const res = mockResponse();
      const sanitizer = createSanitizer({ mode: 'sanitize' });

      sanitizer(req as Request, res as Response, mockNext);

      expect(((req.body as { query: string }).query).toUpperCase()).not.toContain('DROP');
      expect(mockNext).toHaveBeenCalled();
    });

    it('should block prototype pollution in req.body', () => {
      // Object literals cannot create a real __proto__ own-key in V8.
      // JSON.parse() creates a plain object with __proto__ as an actual own key.
      const body = JSON.parse('{"__proto__":{"admin":true},"constructor":{"prototype":{"admin":true}},"name":"test"}');
      const req = mockRequest({ body });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      sanitizer(req as Request, res as Response, mockNext);

      const sanitized = req.body as Record<string, unknown>;
      expect(Object.hasOwn(sanitized, '__proto__')).toBe(false);
      expect(Object.hasOwn(sanitized, 'constructor')).toBe(false);
      expect(sanitized.name).toBe('test');
    });

    it('should block NoSQL operators in req.body', () => {
      const req = mockRequest({
        body: {
          $gt: '',
          $where: 'function() { return true }',
          name: 'test',
        },
      });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      sanitizer(req as Request, res as Response, mockNext);

      const body = req.body as Record<string, unknown>;
      expect(body.$gt).toBeUndefined();
      expect(body.$where).toBeUndefined();
      expect(body.name).toBe('test');
    });
  });

  describe('Query Sanitization', () => {
    it('should sanitize req.query (sanitize mode)', () => {
      const req = mockRequest({ query: { search: "'; DROP TABLE users;--" } });
      const res = mockResponse();
      const sanitizer = createSanitizer({ mode: 'sanitize' });

      sanitizer(req as Request, res as Response, mockNext);

      expect(((req.query as { search: string }).search).toUpperCase()).not.toContain('DROP');
    });

    it('should sanitize XSS in req.query', () => {
      const req = mockRequest({ query: { q: '<script>alert(1)</script>' } });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      sanitizer(req as Request, res as Response, mockNext);

      expect((req.query as { q: string }).q).not.toContain('<script>');
    });
  });

  describe('Params Sanitization', () => {
    it('should sanitize req.params', () => {
      const req = mockRequest({ params: { id: '<script>alert(1)</script>' } });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      sanitizer(req as Request, res as Response, mockNext);

      expect((req.params as { id: string }).id).not.toContain('<script>');
    });
  });

  describe('Nested Object Sanitization', () => {
    it('should sanitize nested objects (sanitize mode)', () => {
      const req = mockRequest({
        body: {
          user: {
            name: '<script>xss</script>',
            profile: {
              bio: "'; DROP TABLE users;--",
            },
          },
        },
      });
      const res = mockResponse();
      const sanitizer = createSanitizer({ mode: 'sanitize' });

      sanitizer(req as Request, res as Response, mockNext);

      const body = req.body as { user: { name: string; profile: { bio: string } } };
      expect(body.user.name).not.toContain('<script>');
      expect(body.user.profile.bio.toUpperCase()).not.toContain('DROP');
    });

    it('should sanitize arrays (sanitize mode)', () => {
      const req = mockRequest({
        body: {
          items: ['<script>alert(1)</script>', 'normal', "'; DROP TABLE users;--"],
        },
      });
      const res = mockResponse();
      const sanitizer = createSanitizer({ mode: 'sanitize' });

      sanitizer(req as Request, res as Response, mockNext);

      const body = req.body as { items: string[] };
      expect(body.items[0]).not.toContain('<script>');
      expect(body.items[1]).toBe('normal');
      expect(body.items[2].toUpperCase()).not.toContain('DROP');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty body', () => {
      const req = mockRequest({ body: {} });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      expect(() => sanitizer(req as Request, res as Response, mockNext)).not.toThrow();
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle null values', () => {
      const req = mockRequest({ body: { value: null } });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      expect(() => sanitizer(req as Request, res as Response, mockNext)).not.toThrow();
      expect((req.body as { value: null }).value).toBeNull();
    });

    it('should handle undefined values', () => {
      const req = mockRequest({ body: { value: undefined } });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      expect(() => sanitizer(req as Request, res as Response, mockNext)).not.toThrow();
    });

    it('should preserve numbers', () => {
      const req = mockRequest({ body: { count: 42 } });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      sanitizer(req as Request, res as Response, mockNext);

      expect((req.body as { count: number }).count).toBe(42);
    });

    it('should preserve booleans', () => {
      const req = mockRequest({ body: { active: true } });
      const res = mockResponse();
      const sanitizer = createSanitizer();

      sanitizer(req as Request, res as Response, mockNext);

      expect((req.body as { active: boolean }).active).toBe(true);
    });
  });
});

describe('Integration: Sanitizer Middleware', () => {
  let testServer: TestServer;

  it('should sanitize POST body', async () => {
    testServer = await createTestServer((app) => {
      app.use(createSanitizer());
      app.post('/echo', (req, res) => {
        res.json({ body: req.body });
      });
    });

    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: '<script>alert("xss")</script>' }),
    });

    const data = await res.json();
    expect(data.body.name).not.toContain('<script>');

    await testServer.close();
  });

  it('should sanitize query parameters', async () => {
    testServer = await createTestServer((app) => {
      app.use(createSanitizer());
      app.get('/search', (req, res) => {
        res.json({ query: req.query });
      });
    });

    const res = await fetch(
      `${testServer.url}/search?q=${encodeURIComponent('<script>alert(1)</script>')}`
    );

    const data = await res.json();
    expect(data.query.q).not.toContain('<script>');

    await testServer.close();
  });
});
