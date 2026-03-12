/**
 * @module @arcis/node/middleware/cors
 * Safe CORS middleware with secure defaults
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

/** CORS configuration options */
export interface CorsOptions {
  /**
   * Allowed origins. Can be:
   * - A string: exact match (e.g., 'https://example.com')
   * - An array: whitelist of allowed origins
   * - A RegExp: pattern match (use with care)
   * - A function: custom validation `(origin) => boolean`
   * - `true`: reflect the request origin (DANGEROUS — only for dev)
   *
   * Default: none (no origin allowed). You must explicitly set this.
   */
  origin: string | string[] | RegExp | ((origin: string) => boolean) | true;

  /** Allowed HTTP methods. Default: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'] */
  methods?: string[];

  /** Allowed headers. Default: ['Content-Type', 'Authorization'] */
  allowedHeaders?: string[];

  /** Headers exposed to the browser. Default: [] */
  exposedHeaders?: string[];

  /** Allow credentials (cookies, authorization headers). Default: false */
  credentials?: boolean;

  /** Preflight cache duration in seconds. Default: 600 (10 minutes) */
  maxAge?: number;

  /** Respond to preflight with 204 (no content). Default: true */
  preflightContinue?: boolean;
}

const DEFAULT_METHODS = ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'];
const DEFAULT_HEADERS = ['Content-Type', 'Authorization'];
const DEFAULT_MAX_AGE = 600;

/**
 * Check if an origin is allowed by the configured policy.
 */
function isOriginAllowed(
  requestOrigin: string,
  allowed: CorsOptions['origin']
): boolean {
  // 'null' origin is always blocked — sent by sandboxed iframes, data: URIs, etc.
  if (requestOrigin === 'null') return false;

  if (allowed === true) return true;

  if (typeof allowed === 'string') {
    return requestOrigin === allowed;
  }

  if (Array.isArray(allowed)) {
    return allowed.includes(requestOrigin);
  }

  if (allowed instanceof RegExp) {
    return allowed.test(requestOrigin);
  }

  if (typeof allowed === 'function') {
    return allowed(requestOrigin);
  }

  return false;
}

/**
 * Create safe CORS middleware.
 *
 * Unlike permissive CORS libraries, this enforces secure defaults:
 * - No wildcard `*` when credentials are enabled
 * - `null` origin is always blocked
 * - `Vary: Origin` is always set for proper caching
 * - You must explicitly configure allowed origins
 *
 * @param options - CORS configuration
 * @returns Express middleware
 *
 * @example
 * // Allow a single origin
 * app.use(safeCors({ origin: 'https://myapp.com' }));
 *
 * @example
 * // Allow multiple origins with credentials
 * app.use(safeCors({
 *   origin: ['https://myapp.com', 'https://admin.myapp.com'],
 *   credentials: true,
 * }));
 *
 * @example
 * // Development: allow all (NOT for production)
 * app.use(safeCors({ origin: true }));
 */
export function safeCors(options: CorsOptions): RequestHandler {
  const {
    origin,
    methods = DEFAULT_METHODS,
    allowedHeaders = DEFAULT_HEADERS,
    exposedHeaders = [],
    credentials = false,
    maxAge = DEFAULT_MAX_AGE,
    preflightContinue = true,
  } = options;

  return (req: Request, res: Response, next: NextFunction) => {
    const requestOrigin = req.headers.origin;

    // Always set Vary: Origin for proper caching
    res.setHeader('Vary', 'Origin');

    // No origin header = same-origin request, skip CORS headers
    if (!requestOrigin) {
      return next();
    }

    const allowed = isOriginAllowed(requestOrigin, origin);

    if (!allowed) {
      // Don't set any CORS headers — browser will block the request
      return next();
    }

    // Set Access-Control-Allow-Origin to the specific origin (not *)
    res.setHeader('Access-Control-Allow-Origin', requestOrigin);

    if (credentials) {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }

    if (exposedHeaders.length > 0) {
      res.setHeader('Access-Control-Expose-Headers', exposedHeaders.join(', '));
    }

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', methods.join(', '));
      res.setHeader('Access-Control-Allow-Headers', allowedHeaders.join(', '));
      res.setHeader('Access-Control-Max-Age', String(maxAge));

      if (preflightContinue) {
        res.status(204).end();
        return;
      }
    }

    next();
  };
}

/**
 * Alias for safeCors
 * @see safeCors
 */
export const createCors = safeCors;
