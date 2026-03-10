import { L as LogOptions, S as SafeLogger } from '../types-D7WNLpcY.mjs';
import 'express';

/**
 * @module @arcis/node/logging/redactor
 * Safe logging with PII/secret redaction
 */

/**
 * Create a safe logger that redacts sensitive data and prevents log injection.
 *
 * @param options - Logger configuration
 * @returns SafeLogger instance
 *
 * @example
 * const logger = createSafeLogger();
 * logger.info('User login', { email: 'user@test.com', password: 'secret' });
 * // Logs: { "email": "user@test.com", "password": "[REDACTED]" }
 *
 * @example
 * // With custom redact keys
 * const logger = createSafeLogger({ redactKeys: ['customToken', 'internalId'] });
 */
declare function createSafeLogger(options?: LogOptions): SafeLogger;
/**
 * Create a redactor function for custom use.
 *
 * @param sensitiveKeys - Keys to redact
 * @returns Redactor function
 */
declare function createRedactor(sensitiveKeys?: string[]): (obj: unknown) => unknown;
/**
 * Alias for createSafeLogger
 * @see createSafeLogger
 */
declare const safeLog: typeof createSafeLogger;

export { createRedactor, createSafeLogger, safeLog };
