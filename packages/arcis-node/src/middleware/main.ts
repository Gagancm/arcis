/**
 * @module @arcis/node/middleware/main
 * Main arcis() middleware factory
 */

import type { RequestHandler } from 'express';
import type { 
  ArcisOptions, 
  ArcisFunction,
  HeaderOptions,
  RateLimitOptions,
  SanitizeOptions,
} from '../core/types';
import { createHeaders } from './headers';
import { createRateLimiter } from './rate-limit';
import { createErrorHandler } from './error-handler';
import { createSanitizer } from '../sanitizers';
import { validate } from '../validation';
import { createSafeLogger } from '../logging';

/**
 * Create Arcis middleware with all protections enabled.
 * 
 * @param options - Configuration options
 * @returns Array of Express middleware
 * 
 * @example
 * // Full protection (recommended)
 * app.use(arcis());
 * 
 * @example
 * // Custom configuration
 * app.use(arcis({
 *   rateLimit: { max: 50 },
 *   headers: { frameOptions: 'SAMEORIGIN' }
 * }));
 * 
 * @example
 * // Disable specific features
 * app.use(arcis({
 *   rateLimit: false,
 *   sanitize: { sql: false }
 * }));
 * 
 * @example
 * // Cleanup on shutdown
 * const middleware = arcis();
 * app.use(middleware);
 * process.on('SIGTERM', () => (middleware as any).close?.());
 */
export function arcis(options: ArcisOptions = {}): RequestHandler[] {
  const middlewares: RequestHandler[] = [];
  const cleanupFns: (() => void)[] = [];

  // Security headers (first, always)
  if (options.headers !== false) {
    const headerOpts: HeaderOptions = typeof options.headers === 'object' 
      ? options.headers 
      : {};
    middlewares.push(createHeaders(headerOpts));
  }

  // Rate limiting
  if (options.rateLimit !== false) {
    const rateLimitOpts: RateLimitOptions = typeof options.rateLimit === 'object' 
      ? options.rateLimit 
      : {};
    const rateLimiter = createRateLimiter(rateLimitOpts);
    middlewares.push(rateLimiter);
    cleanupFns.push(() => rateLimiter.close());
  }

  // Input sanitization (last, after body parsing)
  if (options.sanitize !== false) {
    const sanitizeOpts: SanitizeOptions = typeof options.sanitize === 'object' 
      ? options.sanitize 
      : {};
    middlewares.push(createSanitizer(sanitizeOpts));
  }

  // Add close method to clean up resources
  const result = middlewares as RequestHandler[] & { close?: () => void };
  result.close = () => {
    for (const fn of cleanupFns) {
      fn();
    }
  };

  return result;
}

// Attach individual functions for granular use
const arcisWithMethods = arcis as ArcisFunction;
arcisWithMethods.sanitize = createSanitizer;
arcisWithMethods.rateLimit = createRateLimiter;
arcisWithMethods.headers = createHeaders;
arcisWithMethods.validate = validate;
arcisWithMethods.logger = createSafeLogger;
arcisWithMethods.errorHandler = createErrorHandler;

export { arcisWithMethods as arcisFunction };
export default arcisWithMethods;
