/**
 * Error Handler Middleware Tests
 * Tests for src/middleware/error-handler.ts
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { errorHandler, createErrorHandler } from '../../src/middleware/error-handler';
import { mockRequest, mockResponse, createTestServer, TestServer } from '../setup';

describe('errorHandler', () => {
  describe('Production Mode (isDev: false)', () => {
    it('should hide error details', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error = new Error('Database connection failed at 10.0.0.1');

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Internal Server Error',
        })
      );
      
      // Should not contain sensitive details
      const jsonCall = res.json.mock.calls[0][0];
      expect(jsonCall.stack).toBeUndefined();
      expect(jsonCall.details).toBeUndefined();
      expect(JSON.stringify(jsonCall)).not.toContain('10.0.0.1');
    });

    it('should use error statusCode if provided', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error: Error & { statusCode?: number; expose?: boolean } = new Error('Not found');
      error.statusCode = 404;
      error.expose = true;

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Not found',
        })
      );
    });

    it('should use error status if statusCode not provided', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error: Error & { status?: number } = new Error('Forbidden');
      error.status = 403;

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(403);
    });

    it('should default to 500 status', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(false);
      const error = new Error('Unknown error');

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.status).toHaveBeenCalledWith(500);
    });
  });

  describe('Development Mode (isDev: true)', () => {
    it('should include error details', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(true);
      const error = new Error('Something broke');

      handler(error, req as Request, res as Response, next as NextFunction);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          details: 'Something broke',
        })
      );
    });

    it('should include stack trace', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = vi.fn();
      const handler = errorHandler(true);
      const error = new Error('Error with stack');

      handler(error, req as Request, res as Response, next as NextFunction);

      const jsonCall = res.json.mock.calls[0][0];
      expect(jsonCall.stack).toBeDefined();
    });
  });

  describe('Boolean Shorthand', () => {
    it('should accept false for production mode', () => {
      const handler = errorHandler(false);
      expect(typeof handler).toBe('function');
    });

    it('should accept true for development mode', () => {
      const handler = errorHandler(true);
      expect(typeof handler).toBe('function');
    });
  });
});

describe('createErrorHandler', () => {
  it('should accept options object', () => {
    const handler = createErrorHandler({ isDev: false });
    expect(typeof handler).toBe('function');
  });

  it('should respect isDev option', () => {
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = createErrorHandler({ isDev: true });
    const error = new Error('Test error');

    handler(error, req as Request, res as Response, next as NextFunction);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        details: 'Test error',
      })
    );
  });

  it('should log errors when logErrors is true', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const req = mockRequest();
    const res = mockResponse();
    const next = vi.fn();
    const handler = createErrorHandler({ isDev: false, logErrors: true });
    const error = new Error('Logged error');

    handler(error, req as Request, res as Response, next as NextFunction);

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});

describe('Integration: Error Handler', () => {
  let testServer: TestServer;

  it('should handle errors in production mode', async () => {
    testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Database connection failed');
      });
      app.use(errorHandler(false));
    });

    const res = await fetch(`${testServer.url}/error`);

    expect(res.status).toBe(500);
    const data = await res.json();
    expect(data.error).toBe('Internal Server Error');
    expect(data.stack).toBeUndefined();
    expect(JSON.stringify(data)).not.toContain('Database');

    await testServer.close();
  });

  it('should handle errors in development mode', async () => {
    testServer = await createTestServer((app) => {
      app.get('/error', () => {
        throw new Error('Something broke');
      });
      app.use(errorHandler(true));
    });

    const res = await fetch(`${testServer.url}/error`);

    expect(res.status).toBe(500);
    const data = await res.json();
    expect(data.details).toBe('Something broke');

    await testServer.close();
  });

  it('should handle custom status codes', async () => {
    testServer = await createTestServer((app) => {
      app.get('/not-found', () => {
        const error: Error & { statusCode?: number } = new Error('Resource not found');
        error.statusCode = 404;
        throw error;
      });
      app.use(errorHandler(false));
    });

    const res = await fetch(`${testServer.url}/not-found`);

    expect(res.status).toBe(404);

    await testServer.close();
  });
});
