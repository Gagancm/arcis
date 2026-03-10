import { RequestHandler, Request, Response, NextFunction } from 'express';
import { b as ArcisOptions, A as ArcisFunction, e as RateLimitOptions, h as RateLimiterMiddleware, H as HeaderOptions, E as ErrorHandlerOptions } from '../types-D7WNLpcY.mjs';

/**
 * @module @arcis/node/middleware/main
 * Main arcis() middleware factory
 */

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
declare function arcis(options?: ArcisOptions): RequestHandler[];
declare const arcisWithMethods: ArcisFunction;

/**
 * @module @arcis/node/middleware/rate-limit
 * Rate limiting middleware
 */

/**
 * Create Express middleware for rate limiting.
 *
 * @param options - Rate limit configuration
 * @returns Express middleware with cleanup method
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
 *
 * @example
 * // Cleanup on shutdown
 * const limiter = createRateLimiter();
 * app.use(limiter);
 * process.on('SIGTERM', () => limiter.close());
 */
declare function createRateLimiter(options?: RateLimitOptions): RateLimiterMiddleware;
/**
 * Alias for createRateLimiter
 * @see createRateLimiter
 */
declare const rateLimit: typeof createRateLimiter;

/**
 * @module @arcis/node/middleware/headers
 * Security headers middleware
 */

/**
 * Create Express middleware for security headers.
 * Sets CSP, HSTS, X-Frame-Options, and other security headers.
 *
 * @param options - Header configuration
 * @returns Express middleware
 *
 * @example
 * app.use(createHeaders());
 *
 * @example
 * app.use(createHeaders({
 *   frameOptions: 'SAMEORIGIN',
 *   contentSecurityPolicy: "default-src 'self'"
 * }));
 */
declare function createHeaders(options?: HeaderOptions): RequestHandler;
/**
 * Alias for createHeaders
 * @see createHeaders
 */
declare const securityHeaders: typeof createHeaders;

/**
 * @module @arcis/node/middleware/error-handler
 * Production-safe error handler middleware
 */

/**
 * Create Express error handler that hides sensitive details in production.
 *
 * @param options - Error handler configuration (or boolean for isDev)
 * @returns Express error handling middleware
 *
 * @example
 * // Production mode (default) - hides error details
 * app.use(errorHandler());
 *
 * @example
 * // Development mode - shows error details and stack traces
 * app.use(errorHandler({ isDev: true }));
 *
 * @example
 * // With custom logger
 * app.use(errorHandler({
 *   isDev: false,
 *   logger: arcis.logger()
 * }));
 */
declare function errorHandler(options?: ErrorHandlerOptions | boolean): (err: Error, req: Request, res: Response, next: NextFunction) => void;
/**
 * Alias for errorHandler
 * @see errorHandler
 */
declare const createErrorHandler: typeof errorHandler;

export { arcis, arcisWithMethods as arcisFunction, createErrorHandler, createHeaders, createRateLimiter, arcisWithMethods as default, errorHandler, rateLimit, securityHeaders };
