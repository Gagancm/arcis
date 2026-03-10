export { A as ArcisFunction, a as ArcisMiddleware, b as ArcisOptions, E as ErrorHandlerOptions, F as FieldValidator, H as HeaderOptions, c as HstsOptions, d as HttpError, L as LogOptions, R as RateLimitEntry, e as RateLimitOptions, f as RateLimitResult, g as RateLimitStore, h as RateLimiterMiddleware, S as SafeLogger, i as SanitizeOptions, j as SanitizeResult, T as ThreatInfo, k as ThreatType, V as ValidationConfig, l as ValidationError, m as ValidationResult, n as ValidationSchema } from '../types-D7WNLpcY.js';
import 'express';

/**
 * @module @arcis/node/core/errors
 * Custom error classes for Arcis
 */
/**
 * Base class for all Arcis errors
 */
declare class ArcisError extends Error {
    readonly statusCode: number;
    readonly code: string;
    constructor(message: string, statusCode?: number, code?: string);
}
/**
 * Error thrown when input validation fails
 */
declare class ValidationError extends ArcisError {
    readonly errors: string[];
    constructor(errors: string[]);
}

/**
 * Error thrown when rate limit is exceeded
 */
declare class RateLimitError extends ArcisError {
    readonly retryAfter: number;
    constructor(message: string, retryAfter: number);
}
/**
 * Error thrown when input is too large
 */
declare class InputTooLargeError extends ArcisError {
    readonly maxSize: number;
    readonly actualSize: number;
    constructor(maxSize: number, actualSize: number);
}
/**
 * Error thrown when security threat is detected
 */
declare class SecurityThreatError extends ArcisError {
    readonly threatType: string;
    readonly pattern: string;
    constructor(threatType: string, pattern: string);
}
/**
 * Error thrown when sanitization fails
 */
declare class SanitizationError extends ArcisError {
    constructor(message: string);
}

/**
 * @module @arcis/node/core/constants
 * Named constants for Arcis - no magic numbers
 */
declare const INPUT: {
    /** Default maximum input size (1MB) */
    readonly DEFAULT_MAX_SIZE: 1000000;
    /** Maximum recursion depth for nested objects */
    readonly MAX_RECURSION_DEPTH: 10;
};
declare const RATE_LIMIT: {
    /** Default window size (1 minute) */
    readonly DEFAULT_WINDOW_MS: 60000;
    /** Default max requests per window */
    readonly DEFAULT_MAX_REQUESTS: 100;
    /** Default HTTP status code for rate limited responses */
    readonly DEFAULT_STATUS_CODE: 429;
    /** Default error message */
    readonly DEFAULT_MESSAGE: "Too many requests, please try again later.";
    /** Minimum window size (1 second) */
    readonly MIN_WINDOW_MS: 1000;
    /** Maximum window size (24 hours) */
    readonly MAX_WINDOW_MS: 86400000;
};
declare const HEADERS: {
    /** Default Content Security Policy */
    readonly DEFAULT_CSP: string;
    /** Default HSTS max age (1 year in seconds) */
    readonly HSTS_MAX_AGE: 31536000;
    /** Default X-Frame-Options value */
    readonly FRAME_OPTIONS: "DENY";
    /** Default X-Content-Type-Options value */
    readonly CONTENT_TYPE_OPTIONS: "nosniff";
    /** Default Referrer-Policy value */
    readonly REFERRER_POLICY: "strict-origin-when-cross-origin";
    /** Default Permissions-Policy value */
    readonly PERMISSIONS_POLICY: "geolocation=(), microphone=(), camera=()";
    /** Default Cache-Control value for security */
    readonly CACHE_CONTROL: "no-store, no-cache, must-revalidate, proxy-revalidate";
};
declare const XSS_PATTERNS: readonly [RegExp, RegExp, RegExp, RegExp, RegExp, RegExp, RegExp, RegExp, RegExp, RegExp];
declare const SQL_PATTERNS: readonly [RegExp, RegExp, RegExp, RegExp, RegExp, RegExp, RegExp, RegExp, RegExp];
declare const PATH_PATTERNS: readonly [RegExp, RegExp, RegExp, RegExp];
declare const COMMAND_PATTERNS: readonly [RegExp, RegExp];
/** Prototype pollution keys to block */
declare const DANGEROUS_PROTO_KEYS: Set<string>;
/** MongoDB operators to block */
declare const NOSQL_DANGEROUS_KEYS: Set<string>;
declare const REDACTION: {
    /** Replacement text for redacted values */
    readonly REPLACEMENT: "[REDACTED]";
    /** Truncation indicator */
    readonly TRUNCATED: "[TRUNCATED]";
    /** Max depth indicator */
    readonly MAX_DEPTH: "[MAX_DEPTH]";
    /** Default max message length */
    readonly DEFAULT_MAX_LENGTH: 10000;
    /** Default sensitive keys to redact */
    readonly SENSITIVE_KEYS: Set<string>;
};
declare const VALIDATION: {
    /** Email regex pattern */
    readonly EMAIL: RegExp;
    /** URL regex pattern */
    readonly URL: RegExp;
    /** UUID regex pattern (v4) */
    readonly UUID: RegExp;
};
declare const ERRORS: {
    /** Generic error message (production) */
    readonly INTERNAL_SERVER_ERROR: "Internal Server Error";
    /** Input too large error */
    readonly INPUT_TOO_LARGE: (maxSize: number) => string;
    /** Validation error messages */
    readonly VALIDATION: {
        readonly REQUIRED: (field: string) => string;
        readonly INVALID_TYPE: (field: string, type: string) => string;
        readonly MIN_LENGTH: (field: string, min: number) => string;
        readonly MAX_LENGTH: (field: string, max: number) => string;
        readonly MIN_VALUE: (field: string, min: number) => string;
        readonly MAX_VALUE: (field: string, max: number) => string;
        readonly INVALID_FORMAT: (field: string) => string;
        readonly INVALID_EMAIL: (field: string) => string;
        readonly INVALID_URL: (field: string) => string;
        readonly INVALID_UUID: (field: string) => string;
        readonly INVALID_ENUM: (field: string, values: unknown[]) => string;
        readonly MIN_ITEMS: (field: string, min: number) => string;
        readonly MAX_ITEMS: (field: string, max: number) => string;
    };
};
declare const BLOCKED: "[BLOCKED]";

export { ArcisError, ValidationError as ArcisValidationError, BLOCKED, COMMAND_PATTERNS, DANGEROUS_PROTO_KEYS, ERRORS, HEADERS, INPUT, InputTooLargeError, NOSQL_DANGEROUS_KEYS, PATH_PATTERNS, RATE_LIMIT, REDACTION, RateLimitError, SQL_PATTERNS, SanitizationError, SecurityThreatError, VALIDATION, XSS_PATTERNS };
