import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { 
  sanitizeString, 
  sanitizeObject, 
  createSanitizer,
  createRateLimiter,
  createHeaders,
  validate,
  createSafeLogger,
} from '../src/index';

// Mock Express objects with proper typing
const mockRequest = (overrides: Record<string, any> = {}): Partial<Request> => ({
  body: {},
  query: {},
  params: {},
  ip: '127.0.0.1',
  socket: { remoteAddress: '127.0.0.1' } as any,
  ...overrides,
});

const mockResponse = (): Partial<Response> & { status: any; json: any; setHeader: any; removeHeader: any } => {
  const res: any = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  res.setHeader = vi.fn().mockReturnValue(res);
  res.removeHeader = vi.fn().mockReturnValue(res);
  return res;
};

const mockNext: NextFunction = vi.fn() as any;

// ========================================
// SANITIZATION TESTS
// ========================================
describe('sanitizeString', () => {
  it('should encode HTML entities', () => {
    const result = sanitizeString('<script>alert("xss")</script>');
    expect(result).not.toContain('<script>');
    expect(result).toContain('&lt;');
  });

  it('should remove javascript: protocol', () => {
    const result = sanitizeString('javascript:alert(1)');
    expect(result.toLowerCase()).not.toContain('javascript:');
  });

  it('should remove event handlers', () => {
    const result = sanitizeString('<img onerror="alert(1)">');
    expect(result).not.toContain('onerror');
  });

  it('should remove SQL keywords', () => {
    const result = sanitizeString("'; DROP TABLE users; --");
    expect(result.toUpperCase()).not.toContain('DROP');
  });

  it('should remove path traversal', () => {
    const result = sanitizeString('../../etc/passwd');
    expect(result).not.toContain('../');
  });
});

describe('sanitizeObject', () => {
  it('should sanitize nested objects', () => {
    const input = {
      name: '<script>alert(1)</script>',
      nested: {
        value: "'; DROP TABLE users;--",
      },
    };
    const result = sanitizeObject(input) as any;
    expect(result.name).not.toContain('<script>');
    expect(result.nested.value.toUpperCase()).not.toContain('DROP');
  });

  it('should block prototype pollution', () => {
    const input = {
      __proto__: { admin: true },
      constructor: { prototype: { admin: true } },
      name: 'test',
    };
    const result = sanitizeObject(input) as Record<string, unknown>;
    // Use Object.hasOwn to check for own properties (not prototype chain)
    expect(Object.hasOwn(result, '__proto__')).toBe(false);
    expect(Object.hasOwn(result, 'constructor')).toBe(false);
    expect(result.name).toBe('test');
  });

  it('should block MongoDB operators in keys', () => {
    const input = {
      $gt: '',
      $where: 'function() { return true }',
      name: 'test',
    };
    const result = sanitizeObject(input) as any;
    expect(result.$gt).toBeUndefined();
    expect(result.$where).toBeUndefined();
    expect(result.name).toBe('test');
  });

  it('should handle arrays', () => {
    const input = ['<script>alert(1)</script>', 'normal'];
    const result = sanitizeObject(input) as any;
    expect(result[0]).not.toContain('<script>');
    expect(result[1]).toBe('normal');
  });
});

describe('createSanitizer middleware', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should sanitize req.body', () => {
    const req = mockRequest({ body: { name: '<script>xss</script>' } });
    const res = mockResponse();
    const sanitizer = createSanitizer();

    sanitizer(req as Request, res as Response, mockNext);

    expect((req.body as any).name).not.toContain('<script>');
    expect(mockNext).toHaveBeenCalled();
  });

  it('should sanitize req.query', () => {
    const req = mockRequest({ query: { search: "'; DROP TABLE users;--" } });
    const res = mockResponse();
    const sanitizer = createSanitizer();

    sanitizer(req as Request, res as Response, mockNext);

    expect(((req.query as any).search as string).toUpperCase()).not.toContain('DROP');
    expect(mockNext).toHaveBeenCalled();
  });
});

// ========================================
// RATE LIMITER TESTS
// ========================================
describe('createRateLimiter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should allow requests under the limit', async () => {
    const req = mockRequest();
    const res = mockResponse();
    const limiter = createRateLimiter({ max: 5, windowMs: 60000 });

    await limiter(req as Request, res as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalledWith(429);
    limiter.close();
  });

  it('should set rate limit headers', async () => {
    const req = mockRequest();
    const res = mockResponse();
    const limiter = createRateLimiter({ max: 100 });

    await limiter(req as Request, res as Response, mockNext);

    expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '100');
    expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', expect.any(String));
    limiter.close();
  });

  it('should block requests over the limit', async () => {
    const limiter = createRateLimiter({ max: 2, windowMs: 60000 });

    // Make 3 requests from same IP
    for (let i = 0; i < 3; i++) {
      const req = mockRequest({ ip: '192.168.1.1' });
      const res = mockResponse();
      vi.clearAllMocks();
      await limiter(req as Request, res as Response, mockNext);

      if (i < 2) {
        expect(mockNext).toHaveBeenCalled();
      } else {
        expect(res.status).toHaveBeenCalledWith(429);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
          error: expect.any(String),
        }));
      }
    }
    limiter.close();
  });

  it('should skip requests when skip function returns true', async () => {
    const req = mockRequest();
    const res = mockResponse();
    const limiter = createRateLimiter({ 
      max: 1, 
      skip: () => true,
    });

    // Make multiple requests - all should pass due to skip
    await limiter(req as Request, res as Response, mockNext);
    await limiter(req as Request, res as Response, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(2);
    limiter.close();
  });
});

// ========================================
// SECURITY HEADERS TESTS
// ========================================
describe('createHeaders', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should set default security headers', () => {
    const req = mockRequest();
    const res = mockResponse();
    const headers = createHeaders();

    headers(req as Request, res as Response, mockNext);

    expect(res.setHeader).toHaveBeenCalledWith('Content-Security-Policy', expect.any(String));
    expect(res.setHeader).toHaveBeenCalledWith('X-XSS-Protection', '1; mode=block');
    expect(res.setHeader).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff');
    expect(res.setHeader).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
    expect(res.setHeader).toHaveBeenCalledWith('Strict-Transport-Security', expect.stringContaining('max-age='));
    expect(res.removeHeader).toHaveBeenCalledWith('X-Powered-By');
    expect(mockNext).toHaveBeenCalled();
  });

  it('should allow custom CSP', () => {
    const req = mockRequest();
    const res = mockResponse();
    const customCSP = "default-src 'none'";
    const headers = createHeaders({ contentSecurityPolicy: customCSP });

    headers(req as Request, res as Response, mockNext);

    expect(res.setHeader).toHaveBeenCalledWith('Content-Security-Policy', customCSP);
  });

  it('should allow disabling headers', () => {
    const req = mockRequest();
    const res = mockResponse();
    const headers = createHeaders({ 
      contentSecurityPolicy: false as any,
      xssFilter: false,
      frameOptions: false,
    });

    headers(req as Request, res as Response, mockNext);

    const setCalls = res.setHeader.mock.calls.map((c: any[]) => c[0]);
    expect(setCalls).not.toContain('Content-Security-Policy');
    expect(setCalls).not.toContain('X-XSS-Protection');
    expect(setCalls).not.toContain('X-Frame-Options');
  });
});

// ========================================
// VALIDATOR TESTS
// ========================================
describe('validate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should validate required fields', () => {
    const req = mockRequest({ body: {} });
    const res = mockResponse();
    const validator = validate({ email: { type: 'email', required: true } });

    validator(req as Request, res as Response, mockNext);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ errors: ['email is required'] });
  });

  it('should validate email format', () => {
    const req = mockRequest({ body: { email: 'not-an-email' } });
    const res = mockResponse();
    const validator = validate({ email: { type: 'email', required: true } });

    validator(req as Request, res as Response, mockNext);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ errors: ['email must be a valid email'] });
  });

  it('should validate string min/max length', () => {
    const req = mockRequest({ body: { name: 'ab' } });
    const res = mockResponse();
    const validator = validate({ name: { type: 'string', min: 3 } });

    validator(req as Request, res as Response, mockNext);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ errors: ['name must be at least 3 characters'] });
  });

  it('should validate number ranges', () => {
    const req = mockRequest({ body: { age: -5 } });
    const res = mockResponse();
    const validator = validate({ age: { type: 'number', min: 0 } });

    validator(req as Request, res as Response, mockNext);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ errors: ['age must be at least 0'] });
  });

  it('should validate enum values', () => {
    const req = mockRequest({ body: { role: 'superadmin' } });
    const res = mockResponse();
    const validator = validate({ role: { type: 'string', enum: ['user', 'admin'] } });

    validator(req as Request, res as Response, mockNext);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ errors: ['role must be one of: user, admin'] });
  });

  it('should prevent mass assignment', () => {
    const req = mockRequest({ 
      body: { 
        email: 'test@test.com', 
        isAdmin: true,  // Attacker tries to set this
        role: 'admin',  // Not in schema
      } 
    });
    const res = mockResponse();
    const validator = validate({ email: { type: 'email', required: true } });

    validator(req as Request, res as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect((req.body as any).isAdmin).toBeUndefined();
    expect((req.body as any).role).toBeUndefined();
    expect((req.body as any).email).toBeDefined();
  });

  it('should pass valid data', () => {
    const req = mockRequest({ 
      body: { 
        email: 'test@example.com',
        age: 25,
        role: 'user',
      } 
    });
    const res = mockResponse();
    const validator = validate({ 
      email: { type: 'email', required: true },
      age: { type: 'number', min: 0, max: 150 },
      role: { type: 'string', enum: ['user', 'admin'] },
    });

    validator(req as Request, res as Response, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});

// ========================================
// SAFE LOGGER TESTS
// ========================================
describe('createSafeLogger', () => {
  it('should redact sensitive fields', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger();

    logger.info('User login', { email: 'test@test.com', password: 'secret123' });

    const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
    expect(logOutput.data.password).toBe('[REDACTED]');
    expect(logOutput.data.email).toBe('test@test.com');
    
    consoleSpy.mockRestore();
  });

  it('should remove newlines (log injection prevention)', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger();

    logger.info('User: attacker\nAdmin logged in: true');

    const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
    expect(logOutput.message).not.toContain('\n');
    
    consoleSpy.mockRestore();
  });

  it('should truncate long messages', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const logger = createSafeLogger({ maxLength: 50 });

    const longMessage = 'a'.repeat(100);
    logger.info(longMessage);

    const logOutput = JSON.parse(consoleSpy.mock.calls[0][0]);
    expect(logOutput.message.length).toBeLessThan(100);
    expect(logOutput.message).toContain('[TRUNCATED]');
    
    consoleSpy.mockRestore();
  });
});
