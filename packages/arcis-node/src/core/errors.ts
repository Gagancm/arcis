/**
 * @module @arcis/node/core/errors
 * Custom error classes for Arcis
 */

/**
 * Base class for all Arcis errors
 */
export class ArcisError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(message: string, statusCode = 500, code = 'ARCIS_ERROR') {
    super(message);
    this.name = 'ArcisError';
    this.statusCode = statusCode;
    this.code = code;
    
    // Maintains proper stack trace for where error was thrown (V8 engines)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

/**
 * Error thrown when input validation fails
 */
export class ValidationError extends ArcisError {
  public readonly errors: string[];

  constructor(errors: string[]) {
    super('Validation failed', 400, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

/** Alias for ValidationError (backwards compatibility) */
export { ValidationError as ArcisValidationError };

/**
 * Error thrown when rate limit is exceeded
 */
export class RateLimitError extends ArcisError {
  public readonly retryAfter: number;

  constructor(message: string, retryAfter: number) {
    super(message, 429, 'RATE_LIMIT_EXCEEDED');
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Error thrown when input is too large
 */
export class InputTooLargeError extends ArcisError {
  public readonly maxSize: number;
  public readonly actualSize: number;

  constructor(maxSize: number, actualSize: number) {
    super(`Input exceeds maximum size of ${maxSize} bytes`, 413, 'INPUT_TOO_LARGE');
    this.name = 'InputTooLargeError';
    this.maxSize = maxSize;
    this.actualSize = actualSize;
  }
}

/**
 * Error thrown when security threat is detected
 */
export class SecurityThreatError extends ArcisError {
  public readonly threatType: string;
  public readonly pattern: string;

  constructor(threatType: string, pattern: string) {
    super('Request blocked for security reasons', 400, 'SECURITY_THREAT');
    this.name = 'SecurityThreatError';
    this.threatType = threatType;
    this.pattern = pattern;
  }
}

/**
 * Error thrown when sanitization fails
 */
export class SanitizationError extends ArcisError {
  constructor(message: string) {
    super(message, 400, 'SANITIZATION_ERROR');
    this.name = 'SanitizationError';
  }
}
