/**
 * @module @arcis/node/middleware
 * All middleware for Arcis
 */

// Main middleware factory
export { arcis, arcisFunction } from './main';
export { default } from './main';

// Individual middleware
export { createRateLimiter, rateLimit } from './rate-limit';
export { createHeaders, securityHeaders } from './headers';
export { errorHandler, createErrorHandler } from './error-handler';
export { safeCors, createCors } from './cors';
export { secureCookieDefaults, createSecureCookies, enforceSecureCookie } from './cookies';
