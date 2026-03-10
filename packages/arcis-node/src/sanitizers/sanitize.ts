/**
 * @module @arcis/node/sanitizers/sanitize
 * Main sanitization functions that combine all sanitizers
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { INPUT, DANGEROUS_PROTO_KEYS, NOSQL_DANGEROUS_KEYS } from '../core/constants';
import { InputTooLargeError } from '../core/errors';
import type { SanitizeOptions } from '../core/types';
import { sanitizeXss } from './xss';
import { sanitizeSql } from './sql';
import { sanitizePath } from './path';
import { sanitizeCommand } from './command';

/**
 * Sanitize a string value against multiple attack vectors.
 * 
 * Order matters: We do XSS encoding LAST because:
 * 1. Other sanitizers need to see the original patterns (e.g., SQL keywords)
 * 2. HTML encoding is the final safe output transformation
 * 3. Encoded entities like &lt; shouldn't be treated as SQL/command threats
 * 
 * @param value - The string to sanitize
 * @param options - Sanitization options
 * @returns The sanitized string
 * 
 * @example
 * sanitizeString("<script>alert('xss')</script>")
 * // Returns: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
 * 
 * @example
 * sanitizeString("../../etc/passwd")
 * // Returns: "etc/passwd"
 */
export function sanitizeString(value: string, options: SanitizeOptions = {}): string {
  if (typeof value !== 'string') return value;

  // Input size limit to prevent DoS
  const maxSize = options.maxSize ?? INPUT.DEFAULT_MAX_SIZE;
  if (value.length > maxSize) {
    throw new InputTooLargeError(maxSize, value.length);
  }

  let result = value;

  // 1. SQL injection prevention (before XSS encoding)
  if (options.sql !== false) {
    result = sanitizeSql(result);
  }

  // 2. Path traversal prevention
  if (options.path !== false) {
    result = sanitizePath(result);
  }

  // 3. Command injection prevention (before XSS encoding)
  if (options.command !== false) {
    result = sanitizeCommand(result);
  }

  // 4. XSS prevention LAST (HTML encoding is the final transformation)
  // This ensures SQL/command sanitizers see original patterns,
  // and the final output is safely HTML-encoded
  if (options.xss !== false) {
    result = sanitizeXss(result);
  }

  return result;
}

/**
 * Sanitize an object recursively, including nested objects and arrays.
 * Also removes prototype pollution and NoSQL injection keys.
 * 
 * @param obj - The object to sanitize
 * @param options - Sanitization options
 * @returns The sanitized object
 */
export function sanitizeObject(obj: unknown, options: SanitizeOptions = {}): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeString(obj, options);
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(item => sanitizeObject(item, options));

  return sanitizeObjectDepth(obj as Record<string, unknown>, options, 0);
}

/**
 * Internal recursive sanitization with depth tracking.
 */
function sanitizeObjectDepth(
  obj: Record<string, unknown>,
  options: SanitizeOptions,
  depth: number
): Record<string, unknown> {
  if (depth > INPUT.MAX_RECURSION_DEPTH) return obj;

  const result: Record<string, unknown> = {};

  for (const key of Object.keys(obj)) {
    // Prototype pollution protection - always block dangerous keys
    if (options.proto !== false && DANGEROUS_PROTO_KEYS.has(key)) {
      continue;
    }

    // NoSQL injection - skip dangerous MongoDB operators in keys
    if (options.nosql !== false && NOSQL_DANGEROUS_KEYS.has(key)) {
      continue;
    }

    // Sanitize the key itself (XSS only for keys - just encode, don't SQL sanitize keys)
    const sanitizedKey = sanitizeXss(key);

    // Recursively sanitize value
    const value = obj[key];
    if (value === null || value === undefined) {
      result[sanitizedKey] = value;
    } else if (typeof value === 'string') {
      result[sanitizedKey] = sanitizeString(value, options);
    } else if (Array.isArray(value)) {
      result[sanitizedKey] = value.map(item => sanitizeObject(item, options));
    } else if (typeof value === 'object') {
      result[sanitizedKey] = sanitizeObjectDepth(value as Record<string, unknown>, options, depth + 1);
    } else {
      result[sanitizedKey] = value;
    }
  }

  return result;
}

/**
 * Create Express middleware for request sanitization.
 * Sanitizes req.body, req.query, and req.params.
 * 
 * @param options - Sanitization options
 * @returns Express middleware
 * 
 * @example
 * app.use(createSanitizer());
 * 
 * @example
 * app.use(createSanitizer({ xss: true, sql: true, nosql: true }));
 */
export function createSanitizer(options: SanitizeOptions = {}): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction) => {
    try {
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body, options);
      }
      if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObject(req.query, options) as typeof req.query;
      }
      if (req.params && typeof req.params === 'object') {
        req.params = sanitizeObject(req.params, options) as typeof req.params;
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}
