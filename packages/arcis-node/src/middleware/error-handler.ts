/**
 * @module @arcis/node/middleware/error-handler
 * Production-safe error handler middleware
 */

import type { Request, Response, NextFunction } from 'express';
import { ERRORS } from '../core/constants';
import type { ErrorHandlerOptions, HttpError } from '../core/types';

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
export function errorHandler(
  options: ErrorHandlerOptions | boolean = false
): (err: Error, req: Request, res: Response, next: NextFunction) => void {
  const isDev = typeof options === 'boolean' ? options : options.isDev ?? false;
  const logErrors = typeof options === 'object' ? options.logErrors ?? true : true;
  const logger = typeof options === 'object' ? options.logger : undefined;
  const customHandler = typeof options === 'object' ? options.customHandler : undefined;

  return (err: HttpError, req: Request, res: Response, _next: NextFunction) => {
    const statusCode = err.statusCode || err.status || 500;

    // Custom handler takes precedence
    if (customHandler) {
      return customHandler(err, req, res);
    }

    // Log the error
    if (logErrors) {
      const logData = {
        error: err.message,
        stack: err.stack,
        statusCode,
        path: req.path,
        method: req.method,
      };

      if (logger) {
        logger.error('Request error', logData);
      } else {
        console.error('[arcis] Request error:', logData);
      }
    }

    // Build response
    const response: Record<string, unknown> = {
      error: statusCode >= 500 ? ERRORS.INTERNAL_SERVER_ERROR : err.message,
    };

    // Only show details in development
    if (isDev) {
      response.stack = err.stack;
      response.details = err.message;
    }

    res.status(statusCode).json(response);
  };
}

/**
 * Alias for errorHandler
 * @see errorHandler
 */
export const createErrorHandler = errorHandler;
