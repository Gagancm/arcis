/**
 * Safe CORS Middleware Tests
 * Tests for src/middleware/cors.ts
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { safeCors, createCors } from '../../src/middleware/cors';
import { mockRequest, mockResponse } from '../setup';

function callCors(
  corsOptions: Parameters<typeof safeCors>[0],
  reqOverrides: Partial<{ headers: Record<string, string>; method: string }> = {}
) {
  const req = mockRequest(reqOverrides);
  const res = mockResponse();
  const next = vi.fn();
  const middleware = safeCors(corsOptions);
  middleware(req as unknown as Request, res as unknown as Response, next as unknown as NextFunction);
  return { req, res, next };
}

describe('safeCors', () => {
  describe('Origin Validation', () => {
    it('should allow exact string origin', () => {
      const { res } = callCors(
        { origin: 'https://example.com' },
        { headers: { origin: 'https://example.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'https://example.com');
    });

    it('should reject non-matching origin', () => {
      const { res, next } = callCors(
        { origin: 'https://example.com' },
        { headers: { origin: 'https://evil.com' } }
      );
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Access-Control-Allow-Origin');
      expect(next).toHaveBeenCalled();
    });

    it('should allow origin from array whitelist', () => {
      const { res } = callCors(
        { origin: ['https://app.com', 'https://admin.app.com'] },
        { headers: { origin: 'https://admin.app.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'https://admin.app.com');
    });

    it('should reject origin not in array whitelist', () => {
      const { res } = callCors(
        { origin: ['https://app.com'] },
        { headers: { origin: 'https://evil.com' } }
      );
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Access-Control-Allow-Origin');
    });

    it('should allow origin matching regex', () => {
      const { res } = callCors(
        { origin: /^https:\/\/.*\.example\.com$/ },
        { headers: { origin: 'https://app.example.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'https://app.example.com');
    });

    it('should allow origin via function', () => {
      const { res } = callCors(
        { origin: (o: string) => o.endsWith('.myapp.com') },
        { headers: { origin: 'https://api.myapp.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'https://api.myapp.com');
    });

    it('should reflect origin when origin is true', () => {
      const { res } = callCors(
        { origin: true },
        { headers: { origin: 'https://anything.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', 'https://anything.com');
    });
  });

  describe('Null Origin Blocking', () => {
    it('should always block null origin', () => {
      const { res } = callCors(
        { origin: true },
        { headers: { origin: 'null' } }
      );
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Access-Control-Allow-Origin');
    });

    it('should block null origin even with array whitelist', () => {
      const { res } = callCors(
        { origin: ['null', 'https://app.com'] },
        { headers: { origin: 'null' } }
      );
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Access-Control-Allow-Origin');
    });
  });

  describe('Same-Origin Requests', () => {
    it('should skip CORS headers when no origin header', () => {
      const { res, next } = callCors(
        { origin: 'https://example.com' },
        { headers: {} }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Vary', 'Origin');
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Access-Control-Allow-Origin');
      expect(next).toHaveBeenCalled();
    });
  });

  describe('Credentials', () => {
    it('should set credentials header when enabled', () => {
      const { res } = callCors(
        { origin: 'https://app.com', credentials: true },
        { headers: { origin: 'https://app.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Credentials', 'true');
    });

    it('should not set credentials header when disabled', () => {
      const { res } = callCors(
        { origin: 'https://app.com', credentials: false },
        { headers: { origin: 'https://app.com' } }
      );
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Access-Control-Allow-Credentials');
    });
  });

  describe('Vary Header', () => {
    it('should always set Vary: Origin', () => {
      const { res } = callCors(
        { origin: 'https://app.com' },
        { headers: { origin: 'https://app.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Vary', 'Origin');
    });

    it('should set Vary even for rejected origins', () => {
      const { res } = callCors(
        { origin: 'https://app.com' },
        { headers: { origin: 'https://evil.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Vary', 'Origin');
    });
  });

  describe('Preflight Requests', () => {
    it('should handle OPTIONS preflight', () => {
      const { res } = callCors(
        { origin: 'https://app.com' },
        { headers: { origin: 'https://app.com' }, method: 'OPTIONS' }
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, HEAD, PUT, PATCH, POST, DELETE'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization'
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Max-Age', '600');
      expect(res.status).toHaveBeenCalledWith(204);
    });

    it('should use custom methods', () => {
      const { res } = callCors(
        { origin: 'https://app.com', methods: ['GET', 'POST'] },
        { headers: { origin: 'https://app.com' }, method: 'OPTIONS' }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Methods', 'GET, POST');
    });

    it('should use custom allowed headers', () => {
      const { res } = callCors(
        { origin: 'https://app.com', allowedHeaders: ['X-Custom-Header'] },
        { headers: { origin: 'https://app.com' }, method: 'OPTIONS' }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Headers', 'X-Custom-Header');
    });

    it('should use custom max age', () => {
      const { res } = callCors(
        { origin: 'https://app.com', maxAge: 3600 },
        { headers: { origin: 'https://app.com' }, method: 'OPTIONS' }
      );
      expect(res.setHeader).toHaveBeenCalledWith('Access-Control-Max-Age', '3600');
    });
  });

  describe('Exposed Headers', () => {
    it('should set exposed headers', () => {
      const { res } = callCors(
        { origin: 'https://app.com', exposedHeaders: ['X-Request-Id', 'X-Total-Count'] },
        { headers: { origin: 'https://app.com' } }
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Expose-Headers',
        'X-Request-Id, X-Total-Count'
      );
    });

    it('should not set exposed headers when empty', () => {
      const { res } = callCors(
        { origin: 'https://app.com' },
        { headers: { origin: 'https://app.com' } }
      );
      const calls = res.setHeader.mock.calls.map((c: unknown[]) => c[0]);
      expect(calls).not.toContain('Access-Control-Expose-Headers');
    });
  });
});

describe('createCors', () => {
  it('should be an alias for safeCors', () => {
    expect(createCors).toBe(safeCors);
  });
});
