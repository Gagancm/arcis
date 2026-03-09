/**
 * Arcis - One-line security for Node.js apps
 * A cross-platform security library
 *
 * @module @arcis/node
 * @version 1.0.0
 *
 * @example
 * // Full protection (recommended)
 * import { arcis } from '@arcis/node';
 * app.use(arcis());
 *
 * @example
 * // Granular control
 * app.use(arcis.headers());
 * app.use(arcis.rateLimit({ max: 100, windowMs: 60000 }));
 * app.use(arcis.sanitize());
 *
 * @example
 * // With validation
 * app.post('/users', arcis.validate({
 *   email: { type: 'email', required: true },
 *   age: { type: 'number', min: 0, max: 150 }
 * }), handler);
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

// ============================================
// TYPES
// ============================================

/** Main Arcis configuration options */
export interface ArcisOptions {
  /** Enable/configure input sanitization. Default: true */
  sanitize?: boolean | SanitizeOptions;
  /** Enable/configure rate limiting. Default: true */
  rateLimit?: boolean | RateLimitOptions;
  /** Enable/configure security headers. Default: true */
  headers?: boolean | HeaderOptions;
  /** Enable/configure safe logging. Default: true */
  logging?: boolean | LogOptions;
}

/** Sanitization configuration */
export interface SanitizeOptions {
  /** Sanitize XSS attempts. Default: true */
  xss?: boolean;
  /** Sanitize SQL injection attempts. Default: true */
  sql?: boolean;
  /** Sanitize NoSQL injection attempts. Default: true */
  nosql?: boolean;
  /** Sanitize path traversal attempts. Default: true */
  path?: boolean;
  /** Protect against prototype pollution. Default: true */
  proto?: boolean;
  /** Sanitize command injection attempts. Default: true */
  command?: boolean;
  /** Maximum input size in bytes. Default: 1000000 (1MB) */
  maxSize?: number;
}

/** Rate limiting configuration */
export interface RateLimitOptions {
  /** Maximum requests per window. Default: 100 */
  max?: number;
  /** Window size in milliseconds. Default: 60000 (1 minute) */
  windowMs?: number;
  /** Error message when limit exceeded */
  message?: string;
  /** Function to generate rate limit key from request */
  keyGenerator?: (req: Request) => string;
  /** Function to skip rate limiting for certain requests */
  skip?: (req: Request) => boolean;
  /** Optional external store for distributed rate limiting */
  store?: RateLimitStore;
}

/** External store interface for distributed rate limiting */
export interface RateLimitStore {
  get(key: string): Promise<RateLimitEntry | null>;
  set(key: string, entry: RateLimitEntry): Promise<void>;
  increment(key: string): Promise<number>;
}

export interface RateLimitEntry {
  count: number;
  resetTime: number;
}

/** Security headers configuration */
export interface HeaderOptions {
  /** Content Security Policy. true = default, string = custom, false = disabled */
  contentSecurityPolicy?: boolean | string;
  /** Enable X-XSS-Protection header. Default: true */
  xssFilter?: boolean;
  /** Enable X-Content-Type-Options: nosniff. Default: true */
  noSniff?: boolean;
  /** X-Frame-Options value. Default: 'DENY' */
  frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  /** HSTS configuration. Default: true */
  hsts?: boolean | { maxAge: number; includeSubDomains?: boolean; preload?: boolean };
  /** Referrer-Policy value. Default: 'strict-origin-when-cross-origin' */
  referrerPolicy?: string;
  /** Permissions-Policy value */
  permissionsPolicy?: string;
  /** Enable cache-control headers to prevent caching. Default: true.
   *  Pass a string to use a custom Cache-Control value.
   *  e.g. `'public, max-age=3600'` for cacheable API responses. */
  cacheControl?: boolean | string;
}

/** Safe logging configuration */
export interface LogOptions {
  /** Additional keys to redact beyond defaults */
  redactKeys?: string[];
  /** Maximum message length before truncation. Default: 10000 */
  maxLength?: number;
}

/** Validation schema for request data */
export interface ValidationSchema {
  [key: string]: FieldValidator;
}

/** Field validation rules */
export interface FieldValidator {
  /** Expected data type */
  type: 'string' | 'number' | 'boolean' | 'email' | 'url' | 'uuid' | 'array' | 'object';
  /** Whether field is required. Default: false */
  required?: boolean;
  /** Minimum value (number) or length (string/array) */
  min?: number;
  /** Maximum value (number) or length (string/array) */
  max?: number;
  /** Regex pattern for string validation */
  pattern?: RegExp;
  /** Allowed values */
  enum?: any[];
  /** Whether to sanitize the value. Default: true */
  sanitize?: boolean;
  /** Custom validation function */
  custom?: (value: any) => boolean | string;
}

// ============================================
// CONSTANTS
// ============================================

/** Default maximum input size (1MB) */
const DEFAULT_MAX_INPUT_SIZE = 1_000_000;

/** Maximum recursion depth for nested objects */
const MAX_RECURSION_DEPTH = 10;

// ============================================
// PATTERNS (from core/patterns.json)
// ReDoS-safe patterns where possible
// ============================================

// ReDoS-safe XSS patterns (avoiding nested quantifiers)
const XSS_PATTERNS = [
  /<script[^>]*>[\s\S]*?<\/script>/gi,  // ReDoS-safe version
  /javascript:/gi,
  /vbscript:/gi,
  /on\w+\s*=/gi,
  /<iframe/gi,
  /<object/gi,
  /<embed/gi,
  /data:/gi,
  /%3Cscript/gi,           // URL-encoded <script
  /<svg[^>]*onload/gi,     // SVG with onload
];

const SQL_PATTERNS = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b)/gi,
  /(--)|(\/\*)|(\*\/)/g,
  /(;|\|\||&&)/g,
  // More specific boolean injection patterns to avoid false positives (e.g., "Oregon", "Anderson")
  /\bOR\s+\d+\s*=\s*\d+/gi,                              // OR 1=1
  /\bOR\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]/gi,      // OR 'a'='a'
  /\bAND\s+\d+\s*=\s*\d+/gi,                             // AND 1=1
  /\bAND\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]/gi,     // AND 'a'='a'
];

// NoSQL patterns kept for reference but validation happens via NOSQL_DANGEROUS_KEYS
// const NOSQL_PATTERNS = [
//   /\$(?:gt|gte|lt|lte|ne|eq|in|nin|and|or|not|exists|type|regex|where|expr)/i,
// ];

const PATH_PATTERNS = [
  /\.\.\//g,
  /\.\.\\/g,
  /%2e%2e/gi,
  /%252e/gi, // Double URL-encoded
];

const COMMAND_PATTERNS = [
  /[;&|`$()]/g,
  /\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php)\b/gi,
];

const DANGEROUS_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const NOSQL_DANGEROUS_KEYS = new Set([
  '$gt', '$gte', '$lt', '$lte', '$ne', '$eq', '$in', '$nin',
  '$and', '$or', '$not', '$exists', '$type', '$regex', '$where', '$expr'
]);

// ============================================
// 1. INPUT SANITIZER
// ============================================

/**
 * Sanitize a string value against XSS, SQL injection, path traversal, and command injection.
 *
 * @param value - The string to sanitize
 * @param options - Sanitization options
 * @returns The sanitized string
 *
 * @example
 * sanitizeString("<script>alert('xss')</script>")
 * // Returns: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
 */
export function sanitizeString(value: string, options: SanitizeOptions = {}): string {
  if (typeof value !== 'string') return value;

  // Input size limit to prevent DoS
  const maxSize = options.maxSize ?? DEFAULT_MAX_INPUT_SIZE;
  if (value.length > maxSize) {
    throw new Error(`Input exceeds maximum size of ${maxSize} bytes`);
  }

  let result = value;

  // XSS prevention - remove patterns FIRST, then encode
  if (options.xss !== false) {
    // Remove dangerous patterns while they're still detectable
    for (const pattern of XSS_PATTERNS) {
      result = result.replace(pattern, '');
    }

    // THEN encode remaining content
    result = result
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  // SQL injection prevention
  if (options.sql !== false) {
    for (const pattern of SQL_PATTERNS) {
      result = result.replace(pattern, '[BLOCKED]');
    }
  }

  // Path traversal prevention
  if (options.path !== false) {
    for (const pattern of PATH_PATTERNS) {
      result = result.replace(pattern, '');
    }
  }

  // Command injection prevention
  if (options.command !== false) {
    for (const pattern of COMMAND_PATTERNS) {
      result = result.replace(pattern, '[BLOCKED]');
    }
  }

  return result;
}

/**
 * Sanitize an object recursively, including nested objects and arrays.
 *
 * @param obj - The object to sanitize
 * @param options - Sanitization options
 * @returns The sanitized object
 */
export function sanitizeObject(obj: any, options: SanitizeOptions = {}): any {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeString(obj, options);
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(item => sanitizeObject(item, options));

  return sanitizeObjectDepth(obj, options, 0);
}

function sanitizeObjectDepth(obj: Record<string, any>, options: SanitizeOptions, depth: number): Record<string, any> {
  if (depth > MAX_RECURSION_DEPTH) return obj; // Prevent infinite recursion

  const result: Record<string, any> = {};

  for (const key of Object.keys(obj)) {
    // Prototype pollution protection - always block dangerous keys
    if (options.proto !== false && DANGEROUS_PROTO_KEYS.has(key)) {
      continue;
    }

    // NoSQL injection - skip dangerous MongoDB operators in keys
    if (options.nosql !== false && NOSQL_DANGEROUS_KEYS.has(key)) {
      continue;
    }

    // Sanitize the key itself
    const sanitizedKey = sanitizeString(key, { xss: true, sql: false, path: false, command: false });

    // Recursively sanitize value
    const value = obj[key];
    if (value === null || value === undefined) {
      result[sanitizedKey] = value;
    } else if (typeof value === 'string') {
      result[sanitizedKey] = sanitizeString(value, options);
    } else if (Array.isArray(value)) {
      result[sanitizedKey] = value.map(item => sanitizeObject(item, options));
    } else if (typeof value === 'object') {
      result[sanitizedKey] = sanitizeObjectDepth(value, options, depth + 1);
    } else {
      result[sanitizedKey] = value;
    }
  }

  return result;
}

/**
 * Create Express middleware for request sanitization.
 */
export function createSanitizer(options: SanitizeOptions = {}): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body, options);
      }
      if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObject(req.query, options);
      }
      if (req.params && typeof req.params === 'object') {
        req.params = sanitizeObject(req.params, options);
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

// ============================================
// 2. RATE LIMITER
// ============================================

interface InMemoryRateLimitStore {
  [key: string]: { count: number; resetTime: number };
}

interface RateLimiterMiddleware extends RequestHandler {
  /** Clean up the rate limiter (clear interval) */
  close: () => void;
}

/**
 * Create Express middleware for rate limiting.
 *
 * @example
 * app.use(createRateLimiter({ max: 100, windowMs: 60000 }));
 *
 * @example
 * // Skip rate limiting for certain routes
 * app.use(createRateLimiter({
 *   max: 50,
 *   skip: (req) => req.path === '/health'
 * }));
 */
export function createRateLimiter(options: RateLimitOptions = {}): RateLimiterMiddleware {
  const {
    max = 100,
    windowMs = 60 * 1000,
    message = 'Too many requests, please try again later.',
    keyGenerator = (req) => req.ip || req.socket?.remoteAddress || 'unknown',
    skip = () => false,
    store: externalStore,
  } = options;

  const inMemoryStore: InMemoryRateLimitStore = {};

  // Cleanup interval for in-memory store
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const key of Object.keys(inMemoryStore)) {
      if (inMemoryStore[key].resetTime < now) {
        delete inMemoryStore[key];
      }
    }
  }, windowMs);

  // Prevent interval from keeping the process alive (Node.js only)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (cleanupInterval as any).unref?.();

  const handler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (skip(req)) return next();

      const key = keyGenerator(req);
      const now = Date.now();

      let count: number;
      let resetTime: number;

      if (externalStore) {
        // Use external store (e.g., Redis)
        const entry = await externalStore.get(key);
        if (!entry || entry.resetTime < now) {
          await externalStore.set(key, { count: 1, resetTime: now + windowMs });
          count = 1;
          resetTime = now + windowMs;
        } else {
          count = await externalStore.increment(key);
          resetTime = entry.resetTime;
        }
      } else {
        // Use in-memory store
        if (!inMemoryStore[key] || inMemoryStore[key].resetTime < now) {
          inMemoryStore[key] = { count: 1, resetTime: now + windowMs };
        } else {
          inMemoryStore[key].count++;
        }
        count = inMemoryStore[key].count;
        resetTime = inMemoryStore[key].resetTime;
      }

      const remaining = Math.max(0, max - count);
      const resetSeconds = Math.ceil((resetTime - now) / 1000);

      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', max.toString());
      res.setHeader('X-RateLimit-Remaining', remaining.toString());
      res.setHeader('X-RateLimit-Reset', resetSeconds.toString());

      if (count > max) {
        res.setHeader('Retry-After', resetSeconds.toString());
        res.status(429).json({
          error: message,
          retryAfter: resetSeconds,
        });
        return;
      }

      next();
    } catch (error) {
      // Log error but fail open (allow request through) to prevent DoS
      console.error('Rate limiter error:', error);
      next();
    }
  };

  // Attach close method for cleanup
  const middleware = handler as RateLimiterMiddleware;
  middleware.close = () => {
    clearInterval(cleanupInterval);
  };

  return middleware;
}

// ============================================
// 3. SECURITY HEADERS
// ============================================

const DEFAULT_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
].join('; ');

/**
 * Create Express middleware for security headers.
 */
export function createHeaders(options: HeaderOptions = {}): RequestHandler {
  const {
    contentSecurityPolicy = true,
    xssFilter = true,
    noSniff = true,
    frameOptions = 'DENY',
    hsts = true,
    referrerPolicy = 'strict-origin-when-cross-origin',
    permissionsPolicy = 'geolocation=(), microphone=(), camera=()',
    cacheControl = true,
  } = options;

  return (_req: Request, res: Response, next: NextFunction) => {
    // Content Security Policy
    if (contentSecurityPolicy) {
      const csp = typeof contentSecurityPolicy === 'string' ? contentSecurityPolicy : DEFAULT_CSP;
      res.setHeader('Content-Security-Policy', csp);
    }

    // X-XSS-Protection (legacy but still useful for older browsers)
    if (xssFilter) {
      res.setHeader('X-XSS-Protection', '1; mode=block');
    }

    // Prevent MIME type sniffing
    if (noSniff) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
    }

    // Clickjacking protection
    if (frameOptions) {
      res.setHeader('X-Frame-Options', frameOptions);
    }

    // HTTPS enforcement
    if (hsts) {
      const maxAge = typeof hsts === 'object' ? hsts.maxAge : 31536000;
      const includeSubDomains = typeof hsts === 'object' ? hsts.includeSubDomains !== false : true;
      const preload = typeof hsts === 'object' ? hsts.preload : false;

      let hstsValue = `max-age=${maxAge}`;
      if (includeSubDomains) hstsValue += '; includeSubDomains';
      if (preload) hstsValue += '; preload';

      res.setHeader('Strict-Transport-Security', hstsValue);
    }

    // Referrer Policy
    if (referrerPolicy) {
      res.setHeader('Referrer-Policy', referrerPolicy);
    }

    // Permissions Policy
    if (permissionsPolicy) {
      res.setHeader('Permissions-Policy', permissionsPolicy);
    }

    // Additional security headers
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');

    // Cache-Control headers
    if (cacheControl) {
      const cacheControlValue = typeof cacheControl === 'string'
        ? cacheControl
        : 'no-store, no-cache, must-revalidate, proxy-revalidate';
      res.setHeader('Cache-Control', cacheControlValue);
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }

    // Remove fingerprinting headers
    res.removeHeader('X-Powered-By');

    next();
  };
}

// ============================================
// 4. REQUEST VALIDATOR
// ============================================

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const URL_REGEX = /^https?:\/\/[^\s/$.?#].[^\s]*$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Create Express middleware for request validation.
 * Prevents mass assignment by only allowing fields defined in the schema.
 *
 * @example
 * app.post('/users', validate({
 *   email: { type: 'email', required: true },
 *   name: { type: 'string', min: 2, max: 50 },
 *   age: { type: 'number', min: 0, max: 150 },
 *   role: { type: 'string', enum: ['user', 'admin'] }
 * }), handler);
 */
export function validate(
  schema: ValidationSchema,
  source: 'body' | 'query' | 'params' = 'body'
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const data = req[source] || {};
    const errors: string[] = [];
    const validated: Record<string, any> = {};

    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];

      // Required check
      if (rules.required && (value === undefined || value === null || value === '')) {
        errors.push(`${field} is required`);
        continue;
      }

      // Skip optional empty fields
      if (value === undefined || value === null) {
        continue;
      }

      let typedValue = value;
      let isValid = true;

      // Type validation and coercion
      switch (rules.type) {
        case 'string':
          if (typeof value !== 'string') {
            errors.push(`${field} must be a string`);
            isValid = false;
            break;
          }
          if (rules.min !== undefined && value.length < rules.min) {
            errors.push(`${field} must be at least ${rules.min} characters`);
            isValid = false;
          }
          if (rules.max !== undefined && value.length > rules.max) {
            errors.push(`${field} must be at most ${rules.max} characters`);
            isValid = false;
          }
          if (rules.pattern && !rules.pattern.test(value)) {
            errors.push(`${field} format is invalid`);
            isValid = false;
          }
          if (isValid && rules.sanitize !== false) {
            typedValue = sanitizeString(value);
          }
          break;

        case 'number':
          typedValue = Number(value);
          if (isNaN(typedValue)) {
            errors.push(`${field} must be a number`);
            isValid = false;
            break;
          }
          if (rules.min !== undefined && typedValue < rules.min) {
            errors.push(`${field} must be at least ${rules.min}`);
            isValid = false;
          }
          if (rules.max !== undefined && typedValue > rules.max) {
            errors.push(`${field} must be at most ${rules.max}`);
            isValid = false;
          }
          break;

        case 'boolean':
          if (value === 'true' || value === true || value === 1 || value === '1') {
            typedValue = true;
          } else if (value === 'false' || value === false || value === 0 || value === '0') {
            typedValue = false;
          } else {
            errors.push(`${field} must be a boolean`);
            isValid = false;
          }
          break;

        case 'email':
          if (!EMAIL_REGEX.test(String(value))) {
            errors.push(`${field} must be a valid email`);
            isValid = false;
          }
          if (isValid) {
            typedValue = sanitizeString(String(value).toLowerCase().trim());
          }
          break;

        case 'url':
          if (!URL_REGEX.test(String(value))) {
            errors.push(`${field} must be a valid URL`);
            isValid = false;
          }
          if (isValid) {
            typedValue = sanitizeString(String(value));
          }
          break;

        case 'uuid':
          if (!UUID_REGEX.test(String(value))) {
            errors.push(`${field} must be a valid UUID`);
            isValid = false;
          }
          break;

        case 'array':
          if (!Array.isArray(value)) {
            errors.push(`${field} must be an array`);
            isValid = false;
            break;
          }
          if (rules.min !== undefined && value.length < rules.min) {
            errors.push(`${field} must have at least ${rules.min} items`);
            isValid = false;
          }
          if (rules.max !== undefined && value.length > rules.max) {
            errors.push(`${field} must have at most ${rules.max} items`);
            isValid = false;
          }
          break;

        case 'object':
          if (typeof value !== 'object' || Array.isArray(value) || value === null) {
            errors.push(`${field} must be an object`);
            isValid = false;
          }
          break;
      }

      // Enum validation
      if (isValid && rules.enum && !rules.enum.includes(typedValue)) {
        errors.push(`${field} must be one of: ${rules.enum.join(', ')}`);
        isValid = false;
      }

      // Custom validation
      if (isValid && rules.custom) {
        const customResult = rules.custom(typedValue);
        if (customResult !== true) {
          errors.push(typeof customResult === 'string' ? customResult : `${field} is invalid`);
          isValid = false;
        }
      }

      if (isValid) {
        validated[field] = typedValue;
      }
    }

    if (errors.length > 0) {
      res.status(400).json({ errors });
      return;
    }

    // Replace with validated data (prevents mass assignment)
    req[source] = validated;
    next();
  };
}

// ============================================
// 5. SAFE LOGGER
// ============================================

const DEFAULT_REDACT_KEYS = new Set([
  'password', 'passwd', 'pwd', 'secret', 'token', 'apikey',
  'api_key', 'apiKey', 'auth', 'authorization', 'credit_card',
  'creditcard', 'cc', 'ssn', 'social_security', 'private_key',
  'privateKey', 'access_token', 'accessToken', 'refresh_token',
  'refreshToken', 'bearer', 'jwt', 'session', 'cookie',
]);

export interface SafeLogger {
  log: (level: string, message: string, data?: any) => void;
  info: (message: string, data?: any) => void;
  warn: (message: string, data?: any) => void;
  error: (message: string, data?: any) => void;
  debug: (message: string, data?: any) => void;
}

/**
 * Create a safe logger that redacts sensitive data and prevents log injection.
 */
export function createSafeLogger(options: LogOptions = {}): SafeLogger {
  const { redactKeys = [], maxLength = 10000 } = options;

  // Combine default and custom keys
  const allRedactKeys = new Set([
    ...DEFAULT_REDACT_KEYS,
    ...redactKeys.map(k => k.toLowerCase()),
  ]);

  function redact(obj: any, depth = 0): any {
    if (depth > MAX_RECURSION_DEPTH) return '[MAX_DEPTH]';
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
      // Remove newlines and control characters (log injection prevention)
      let safe = obj
        .replace(/[\r\n\t]/g, ' ')
        .replace(/[^\x20-\x7E\u00A0-\u024F]/g, ''); // Keep printable ASCII + common Latin

      if (safe.length > maxLength) {
        safe = safe.substring(0, maxLength) + '...[TRUNCATED]';
      }
      return safe;
    }

    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map(item => redact(item, depth + 1));
    }

    const result: Record<string, any> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (allRedactKeys.has(key.toLowerCase())) {
        result[key] = '[REDACTED]';
      } else {
        result[key] = redact(value, depth + 1);
      }
    }
    return result;
  }

  function log(level: string, message: string, data?: any): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      message: redact(message),
      ...(data !== undefined && { data: redact(data) }),
    };
    console.log(JSON.stringify(entry));
  }

  return {
    log,
    info: (msg: string, data?: any) => log('info', msg, data),
    warn: (msg: string, data?: any) => log('warn', msg, data),
    error: (msg: string, data?: any) => log('error', msg, data),
    debug: (msg: string, data?: any) => log('debug', msg, data),
  };
}

// ============================================
// 6. ERROR HANDLER
// ============================================

export interface ErrorHandlerOptions {
  /** Show stack traces and detailed errors. Default: false */
  isDev?: boolean;
  /** Custom error logger */
  logger?: SafeLogger;
}

/**
 * Create Express error handler that hides sensitive details in production.
 */
export function errorHandler(
  options: ErrorHandlerOptions | boolean = false
): (err: Error, req: Request, res: Response, next: NextFunction) => void {
  const isDev = typeof options === 'boolean' ? options : options.isDev ?? false;
  const logger = typeof options === 'object' ? options.logger : undefined;

  return (err: Error, _req: Request, res: Response, _next: NextFunction) => {
    const statusCode = (err as any).statusCode || (err as any).status || 500;

    // Log the error
    if (logger) {
      logger.error('Request error', {
        error: err.message,
        stack: err.stack,
        statusCode,
      });
    }

    const response: Record<string, any> = {
      error: statusCode >= 500 ? 'Internal Server Error' : err.message,
    };

    // Only show details in development
    if (isDev) {
      response.stack = err.stack;
      response.details = err.message;
    }

    res.status(statusCode).json(response);
  };
}

// ============================================
// MAIN ARCIS MIDDLEWARE
// ============================================

interface ArcisFunction {
  (options?: ArcisOptions): RequestHandler[];
  /** Clean up resources (rate limiter intervals, etc.) */
  close?: () => void;
  sanitize: typeof createSanitizer;
  rateLimit: typeof createRateLimiter;
  headers: typeof createHeaders;
  validate: typeof validate;
  logger: typeof createSafeLogger;
  errorHandler: typeof errorHandler;
}

/**
 * Create Arcis middleware with all protections enabled.
 *
 * @example
 * // Full protection
 * app.use(arcis());
 *
 * @example
 * // Custom configuration
 * app.use(arcis({
 *   rateLimit: { max: 50 },
 *   headers: { frameOptions: 'SAMEORIGIN' }
 * }));
 */
export function arcis(options: ArcisOptions = {}): RequestHandler[] {
  const middlewares: RequestHandler[] = [];
  const cleanupFns: (() => void)[] = [];

  // Security headers (first, always)
  if (options.headers !== false) {
    const headerOpts = typeof options.headers === 'object' ? options.headers : {};
    middlewares.push(createHeaders(headerOpts));
  }

  // Rate limiting
  if (options.rateLimit !== false) {
    const rateLimitOpts = typeof options.rateLimit === 'object' ? options.rateLimit : {};
    const rateLimiter = createRateLimiter(rateLimitOpts);
    middlewares.push(rateLimiter);
    cleanupFns.push(() => rateLimiter.close());
  }

  // Input sanitization (last, after body parsing)
  if (options.sanitize !== false) {
    const sanitizeOpts = typeof options.sanitize === 'object' ? options.sanitize : {};
    middlewares.push(createSanitizer(sanitizeOpts));
  }

  // Add close method to clean up resources
  (middlewares as any).close = () => {
    for (const fn of cleanupFns) {
      fn();
    }
  };

  return middlewares;
}

// Attach individual functions for granular use
const arcisWithMethods = arcis as ArcisFunction;
arcisWithMethods.sanitize = createSanitizer;
arcisWithMethods.rateLimit = createRateLimiter;
arcisWithMethods.headers = createHeaders;
arcisWithMethods.validate = validate;
arcisWithMethods.logger = createSafeLogger;
arcisWithMethods.errorHandler = errorHandler;

export default arcisWithMethods;
