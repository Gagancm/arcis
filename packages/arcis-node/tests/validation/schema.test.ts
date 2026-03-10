/**
 * Schema Validation Tests
 * Tests for src/validation/schema.ts
 */

import { describe, it, expect, vi } from 'vitest';
import type { Request, Response } from 'express';
import { validate, createValidator } from '../../src/validation/schema';
import { mockRequest, mockResponse, mockNext } from '../setup';

describe('validate', () => {
  describe('Required Fields', () => {
    it('should reject missing required fields', async () => {
      const middleware = validate({
        email: { type: 'email', required: true },
      });

      const req = mockRequest({ body: {} });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('required')]),
      });
    });

    it('should reject empty string for required fields', async () => {
      const middleware = validate({
        name: { type: 'string', required: true },
      });

      const req = mockRequest({ body: { name: '' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should reject null for required fields', async () => {
      const middleware = validate({
        name: { type: 'string', required: true },
      });

      const req = mockRequest({ body: { name: null } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should allow optional fields to be missing', async () => {
      const middleware = validate({
        email: { type: 'email', required: true },
        name: { type: 'string', required: false },
      });

      const req = mockRequest({ body: { email: 'test@test.com' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('String Validation', () => {
    it('should validate string type', async () => {
      const middleware = validate({
        name: { type: 'string', required: true },
      });

      const req = mockRequest({ body: { name: 123 } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('string')]),
      });
    });

    it('should validate minimum length', async () => {
      const middleware = validate({
        name: { type: 'string', min: 5 },
      });

      const req = mockRequest({ body: { name: 'abc' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('at least 5')]),
      });
    });

    it('should validate maximum length', async () => {
      const middleware = validate({
        name: { type: 'string', max: 5 },
      });

      const req = mockRequest({ body: { name: 'too long string' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('at most 5')]),
      });
    });

    it('should validate pattern', async () => {
      const middleware = validate({
        code: { type: 'string', pattern: /^[A-Z]{3}$/ },
      });

      const req = mockRequest({ body: { code: 'abc123' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('invalid')]),
      });
    });

    it('should sanitize string values by default', async () => {
      const middleware = validate({
        name: { type: 'string', required: true },
      });

      const req = mockRequest({ body: { name: '<script>alert(1)</script>John' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(req.body.name).not.toContain('<script>');
    });

    it('should skip sanitization when sanitize: false', async () => {
      const middleware = validate({
        html: { type: 'string', required: true, sanitize: false },
      });

      const req = mockRequest({ body: { html: '<p>Hello</p>' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(req.body.html).toBe('<p>Hello</p>');
    });
  });

  describe('Number Validation', () => {
    it('should validate number type', async () => {
      const middleware = validate({
        age: { type: 'number', required: true },
      });

      const req = mockRequest({ body: { age: 'not a number' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('number')]),
      });
    });

    it('should coerce string to number', async () => {
      const middleware = validate({
        age: { type: 'number', required: true },
      });

      const req = mockRequest({ body: { age: '25' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(req.body.age).toBe(25);
    });

    it('should validate minimum value', async () => {
      const middleware = validate({
        age: { type: 'number', min: 0 },
      });

      const req = mockRequest({ body: { age: -5 } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('at least 0')]),
      });
    });

    it('should validate maximum value', async () => {
      const middleware = validate({
        age: { type: 'number', max: 150 },
      });

      const req = mockRequest({ body: { age: 200 } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('at most 150')]),
      });
    });
  });

  describe('Boolean Validation', () => {
    it('should validate boolean type', async () => {
      const middleware = validate({
        active: { type: 'boolean', required: true },
      });

      const req = mockRequest({ body: { active: 'invalid' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should coerce truthy string values to boolean', async () => {
      const middleware = validate({
        active: { type: 'boolean' },
      });

      const testCases = [
        { input: 'true', expected: true },
        { input: true, expected: true },
        { input: 1, expected: true },
        { input: '1', expected: true },
        { input: 'false', expected: false },
        { input: false, expected: false },
        { input: 0, expected: false },
        { input: '0', expected: false },
      ];

      for (const { input, expected } of testCases) {
        const req = mockRequest({ body: { active: input } }) as Request;
        const res = mockResponse();
        vi.clearAllMocks();

        await middleware(req, res as Response, mockNext);

        expect(mockNext).toHaveBeenCalled();
        expect(req.body.active).toBe(expected);
      }
    });
  });

  describe('Email Validation', () => {
    it('should validate email format', async () => {
      const middleware = validate({
        email: { type: 'email', required: true },
      });

      const req = mockRequest({ body: { email: 'not-an-email' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('valid email')]),
      });
    });

    it('should accept valid emails', async () => {
      const middleware = validate({
        email: { type: 'email', required: true },
      });

      const validEmails = ['test@test.com', 'user.name@domain.org', 'a@b.co'];

      for (const email of validEmails) {
        const req = mockRequest({ body: { email } }) as Request;
        const res = mockResponse();
        vi.clearAllMocks();

        await middleware(req, res as Response, mockNext);

        expect(mockNext).toHaveBeenCalled();
      }
    });

    it('should normalize email to lowercase', async () => {
      const middleware = validate({
        email: { type: 'email', required: true },
      });

      // Note: The email validation checks the regex BEFORE normalization
      // Emails with spaces will fail the regex check (/^[^\s@]+@[^\s@]+\.[^\s@]+$/)
      // So we test with a valid email that just needs case normalization
      const req = mockRequest({ body: { email: 'USER@TEST.COM' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(req.body.email).toBe('user@test.com');
    });
  });

  describe('URL Validation', () => {
    it('should validate URL format', async () => {
      const middleware = validate({
        website: { type: 'url', required: true },
      });

      const req = mockRequest({ body: { website: 'not-a-url' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('valid URL')]),
      });
    });

    it('should accept valid URLs', async () => {
      const middleware = validate({
        website: { type: 'url', required: true },
      });

      const validUrls = ['https://example.com', 'http://localhost:3000', 'https://sub.domain.com/path'];

      for (const website of validUrls) {
        const req = mockRequest({ body: { website } }) as Request;
        const res = mockResponse();
        vi.clearAllMocks();

        await middleware(req, res as Response, mockNext);

        expect(mockNext).toHaveBeenCalled();
      }
    });
  });

  describe('UUID Validation', () => {
    it('should validate UUID format', async () => {
      const middleware = validate({
        id: { type: 'uuid', required: true },
      });

      const req = mockRequest({ body: { id: 'not-a-uuid' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('valid UUID')]),
      });
    });

    it('should accept valid UUIDs', async () => {
      const middleware = validate({
        id: { type: 'uuid', required: true },
      });

      const req = mockRequest({ body: { id: '123e4567-e89b-12d3-a456-426614174000' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Array Validation', () => {
    it('should validate array type', async () => {
      const middleware = validate({
        tags: { type: 'array', required: true },
      });

      const req = mockRequest({ body: { tags: 'not an array' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('array')]),
      });
    });

    it('should validate minimum items', async () => {
      const middleware = validate({
        tags: { type: 'array', min: 2 },
      });

      const req = mockRequest({ body: { tags: ['one'] } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('at least 2 items')]),
      });
    });

    it('should validate maximum items', async () => {
      const middleware = validate({
        tags: { type: 'array', max: 3 },
      });

      const req = mockRequest({ body: { tags: ['a', 'b', 'c', 'd', 'e'] } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('at most 3 items')]),
      });
    });
  });

  describe('Object Validation', () => {
    it('should validate object type', async () => {
      const middleware = validate({
        metadata: { type: 'object', required: true },
      });

      const req = mockRequest({ body: { metadata: 'not an object' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should reject arrays for object type', async () => {
      const middleware = validate({
        metadata: { type: 'object', required: true },
      });

      const req = mockRequest({ body: { metadata: [] } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should reject null for object type', async () => {
      const middleware = validate({
        metadata: { type: 'object', required: true },
      });

      const req = mockRequest({ body: { metadata: null } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
    });
  });

  describe('Enum Validation', () => {
    it('should validate enum values', async () => {
      const middleware = validate({
        role: { type: 'string', enum: ['user', 'admin', 'moderator'] },
      });

      const req = mockRequest({ body: { role: 'superadmin' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('one of')]),
      });
    });

    it('should accept valid enum values', async () => {
      const middleware = validate({
        role: { type: 'string', enum: ['user', 'admin'] },
      });

      const req = mockRequest({ body: { role: 'admin' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Custom Validation', () => {
    it('should run custom validator', async () => {
      const middleware = validate({
        password: {
          type: 'string',
          required: true,
          custom: (v) => (v as string).length >= 8 || 'Password must be at least 8 characters',
        },
      });

      const req = mockRequest({ body: { password: 'short' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining(['Password must be at least 8 characters']),
      });
    });

    it('should pass when custom validator returns true', async () => {
      const middleware = validate({
        password: {
          type: 'string',
          required: true,
          custom: (v) => (v as string).length >= 8,
        },
      });

      const req = mockRequest({ body: { password: 'longpassword123' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Mass Assignment Prevention', () => {
    it('should strip unknown fields from body', async () => {
      const middleware = validate({
        email: { type: 'email', required: true },
        name: { type: 'string' },
      });

      const req = mockRequest({
        body: {
          email: 'test@test.com',
          name: 'John',
          isAdmin: true,
          secretField: 'hack',
        },
      }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(req.body.email).toBe('test@test.com');
      expect(req.body.name).toBeDefined();
      expect(req.body.isAdmin).toBeUndefined();
      expect(req.body.secretField).toBeUndefined();
    });
  });

  describe('Source Parameter', () => {
    it('should validate query params when source is "query"', async () => {
      const middleware = validate(
        { q: { type: 'string', required: true, min: 1 } },
        'query'
      );

      const req = mockRequest({ query: {} });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        errors: expect.arrayContaining([expect.stringContaining('required')]),
      });
    });

    it('should validate params when source is "params"', async () => {
      const middleware = validate(
        { id: { type: 'uuid', required: true } },
        'params'
      );

      const req = mockRequest({ params: { id: 'invalid' } });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
    });

    it('should pass valid query params', async () => {
      const middleware = validate(
        { page: { type: 'number', min: 1 } },
        'query'
      );

      const req = mockRequest({ query: { page: '1' } }) as Request;
      const res = mockResponse();
      vi.clearAllMocks();

      await middleware(req, res as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(req.query.page).toBe(1);
    });
  });

  describe('Multiple Errors', () => {
    it('should return all errors at once', async () => {
      const middleware = validate({
        email: { type: 'email', required: true },
        name: { type: 'string', required: true, min: 2 },
        age: { type: 'number', min: 0 },
      });

      const req = mockRequest({
        body: {
          email: 'invalid',
          name: 'A',
          age: -5,
        },
      });
      const res = mockResponse();

      await middleware(req as Request, res as Response, mockNext);

      expect(res.status).toHaveBeenCalledWith(400);
      const jsonCall = res.json.mock.calls[0][0];
      expect(jsonCall.errors.length).toBeGreaterThanOrEqual(3);
    });
  });
});

describe('createValidator', () => {
  it('should be an alias for validate', () => {
    expect(createValidator).toBe(validate);
  });
});
