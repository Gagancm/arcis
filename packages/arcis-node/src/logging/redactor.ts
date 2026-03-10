/**
 * @module @arcis/node/logging/redactor
 * Safe logging with PII/secret redaction
 */

import { REDACTION, INPUT } from '../core/constants';
import type { LogOptions, SafeLogger } from '../core/types';

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
export function createSafeLogger(options: LogOptions = {}): SafeLogger {
  const { 
    redactKeys = [], 
    maxLength = REDACTION.DEFAULT_MAX_LENGTH,
    redactPatterns = [],
  } = options;

  // Combine default and custom keys (lowercase for case-insensitive matching)
  const allRedactKeys = new Set([
    ...Array.from(REDACTION.SENSITIVE_KEYS),
    ...redactKeys.map(k => k.toLowerCase()),
  ]);

  /**
   * Redact sensitive data from an object recursively.
   */
  function redact(obj: unknown, depth = 0): unknown {
    if (depth > INPUT.MAX_RECURSION_DEPTH) return REDACTION.MAX_DEPTH;
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
      return redactString(obj, maxLength, redactPatterns);
    }

    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map(item => redact(item, depth + 1));
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (allRedactKeys.has(key.toLowerCase())) {
        result[key] = REDACTION.REPLACEMENT;
      } else {
        result[key] = redact(value, depth + 1);
      }
    }
    return result;
  }

  /**
   * Log a message at the specified level.
   */
  function log(level: string, message: string, data?: unknown): void {
    const entry: Record<string, unknown> = {
      timestamp: new Date().toISOString(),
      level,
      message: redactString(message, maxLength, redactPatterns),
    };
    
    if (data !== undefined) {
      entry.data = redact(data);
    }
    
    console.log(JSON.stringify(entry));
  }

  return {
    log,
    info: (msg: string, data?: unknown) => log('info', msg, data),
    warn: (msg: string, data?: unknown) => log('warn', msg, data),
    error: (msg: string, data?: unknown) => log('error', msg, data),
    debug: (msg: string, data?: unknown) => log('debug', msg, data),
  };
}

/**
 * Redact a string value.
 * Removes newlines (log injection prevention), applies patterns, and truncates.
 */
function redactString(str: string, maxLength: number, patterns: RegExp[]): string {
  // Remove newlines and control characters (log injection prevention)
  let safe = str
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[^\x20-\x7E\u00A0-\u024F]/g, ''); // Keep printable ASCII + common Latin

  // Apply custom redaction patterns
  for (const pattern of patterns) {
    safe = safe.replace(pattern, REDACTION.REPLACEMENT);
  }

  // Truncate if too long
  if (safe.length > maxLength) {
    safe = safe.substring(0, maxLength) + `...${REDACTION.TRUNCATED}`;
  }

  return safe;
}

/**
 * Create a redactor function for custom use.
 * 
 * @param sensitiveKeys - Keys to redact
 * @returns Redactor function
 */
export function createRedactor(sensitiveKeys: string[] = []): (obj: unknown) => unknown {
  const allKeys = new Set([
    ...Array.from(REDACTION.SENSITIVE_KEYS),
    ...sensitiveKeys.map(k => k.toLowerCase()),
  ]);

  function redact(obj: unknown, depth = 0): unknown {
    if (depth > INPUT.MAX_RECURSION_DEPTH) return REDACTION.MAX_DEPTH;
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;

    if (Array.isArray(obj)) {
      return obj.map(item => redact(item, depth + 1));
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (allKeys.has(key.toLowerCase())) {
        result[key] = REDACTION.REPLACEMENT;
      } else {
        result[key] = redact(value, depth + 1);
      }
    }
    return result;
  }

  return redact;
}

/**
 * Alias for createSafeLogger
 * @see createSafeLogger
 */
export const safeLog = createSafeLogger;
