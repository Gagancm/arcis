import { Request, RequestHandler, Response, NextFunction } from 'express';

/**
 * @module @arcis/node/core/types
 * All TypeScript interfaces and types for Arcis
 */

/** Main Arcis configuration options */
interface ArcisOptions {
    /** Enable/configure input sanitization. Default: true */
    sanitize?: boolean | SanitizeOptions;
    /** Enable/configure rate limiting. Default: true */
    rateLimit?: boolean | RateLimitOptions;
    /** Enable/configure security headers. Default: true */
    headers?: boolean | HeaderOptions;
    /** Enable/configure safe logging. Default: true */
    logging?: boolean | LogOptions;
}
/** Sanitization configuration */
interface SanitizeOptions {
    /** Sanitize XSS attempts. Default: true */
    xss?: boolean;
    /** Sanitize SQL injection attempts. Default: true */
    sql?: boolean;
    /** Sanitize NoSQL injection attempts. Default: true */
    nosql?: boolean;
    /** Sanitize path traversal attempts. Default: true */
    path?: boolean;
    /** Protect against prototype pollution. Default: true */
    proto?: boolean;
    /** Sanitize command injection attempts. Default: true */
    command?: boolean;
    /** Maximum input size in bytes. Default: 1000000 (1MB) */
    maxSize?: number;
}
/** Result of sanitizing a string */
interface SanitizeResult {
    /** The sanitized value */
    value: string;
    /** Whether any sanitization was applied */
    wasSanitized: boolean;
    /** Details about detected threats */
    threats: ThreatInfo[];
}
/** Information about a detected threat */
interface ThreatInfo {
    /** Type of threat detected */
    type: ThreatType;
    /** Pattern that matched */
    pattern: string;
    /** Original matched content */
    original: string;
    /** Location in the input (if applicable) */
    location?: string;
}
/** Types of security threats */
type ThreatType = 'xss' | 'sql_injection' | 'nosql_injection' | 'path_traversal' | 'command_injection' | 'prototype_pollution';
/** Rate limiting configuration */
interface RateLimitOptions {
    /** Maximum requests per window. Default: 100 */
    max?: number;
    /** Window size in milliseconds. Default: 60000 (1 minute) */
    windowMs?: number;
    /** Error message when limit exceeded */
    message?: string;
    /** HTTP status code for rate limited responses. Default: 429 */
    statusCode?: number;
    /** Function to generate rate limit key from request */
    keyGenerator?: (req: Request) => string;
    /** Function to skip rate limiting for certain requests */
    skip?: (req: Request) => boolean;
    /** Optional external store for distributed rate limiting */
    store?: RateLimitStore;
}
/** External store interface for distributed rate limiting */
interface RateLimitStore {
    /** Get current count for a key */
    get(key: string): Promise<RateLimitEntry | null>;
    /** Set entry for a key */
    set(key: string, entry: RateLimitEntry): Promise<void>;
    /** Increment count for a key */
    increment(key: string): Promise<number>;
    /** Decrement count for a key (for sliding window) */
    decrement?(key: string): Promise<void>;
    /** Reset count for a key */
    reset?(key: string): Promise<void>;
    /** Close the store (cleanup connections) */
    close?(): Promise<void>;
}
/** Rate limit entry stored in a store */
interface RateLimitEntry {
    /** Number of requests in the current window */
    count: number;
    /** Timestamp when the window resets */
    resetTime: number;
}
/** Result from incrementing a rate limit counter */
interface RateLimitResult {
    /** Current request count */
    count: number;
    /** When the window resets */
    resetTime: Date;
}
/** Rate limiter middleware with cleanup support */
interface RateLimiterMiddleware extends RequestHandler {
    /** Clean up the rate limiter (clear intervals, close stores) */
    close: () => void;
}
/** Security headers configuration */
interface HeaderOptions {
    /** Content Security Policy. true = default, string = custom, false = disabled */
    contentSecurityPolicy?: boolean | string;
    /** Enable X-XSS-Protection header. Default: true */
    xssFilter?: boolean;
    /** Enable X-Content-Type-Options: nosniff. Default: true */
    noSniff?: boolean;
    /** X-Frame-Options value. Default: 'DENY' */
    frameOptions?: 'DENY' | 'SAMEORIGIN' | false;
    /** HSTS configuration. Default: true */
    hsts?: boolean | HstsOptions;
    /** Referrer-Policy value. Default: 'strict-origin-when-cross-origin' */
    referrerPolicy?: string | false;
    /** Permissions-Policy value */
    permissionsPolicy?: string | false;
    /** Cache-Control configuration. Default: true (no-cache) */
    cacheControl?: boolean | string;
}
/** HSTS (HTTP Strict Transport Security) options */
interface HstsOptions {
    /** Max age in seconds. Default: 31536000 (1 year) */
    maxAge?: number;
    /** Include subdomains. Default: true */
    includeSubDomains?: boolean;
    /** Enable HSTS preload. Default: false */
    preload?: boolean;
}
/** Validation configuration */
interface ValidationConfig {
    /** Strip fields not in schema. Default: true (prevents mass assignment) */
    stripUnknown?: boolean;
    /** Stop on first error. Default: false */
    abortEarly?: boolean;
}
/** Validation schema for request data */
interface ValidationSchema {
    [key: string]: FieldValidator;
}
/** Field validation rules */
interface FieldValidator {
    /** Expected data type */
    type: 'string' | 'number' | 'boolean' | 'email' | 'url' | 'uuid' | 'array' | 'object';
    /** Whether field is required. Default: false */
    required?: boolean;
    /** Minimum value (number) or length (string/array) */
    min?: number;
    /** Maximum value (number) or length (string/array) */
    max?: number;
    /** Regex pattern for string validation */
    pattern?: RegExp;
    /** Allowed values */
    enum?: unknown[];
    /** Whether to sanitize the value. Default: true */
    sanitize?: boolean;
    /** Custom validation function */
    custom?: (value: unknown) => boolean | string;
}
/** Validation result */
interface ValidationResult {
    /** Whether validation passed */
    valid: boolean;
    /** Validation errors */
    errors: ValidationError[];
    /** Validated and sanitized data */
    data: Record<string, unknown>;
}
/** Single validation error */
interface ValidationError {
    /** Field that failed validation */
    field: string;
    /** Human-readable error message */
    message: string;
    /** Error code for programmatic handling */
    code: string;
}
/** Safe logging configuration */
interface LogOptions {
    /** Additional keys to redact beyond defaults */
    redactKeys?: string[];
    /** Maximum message length before truncation. Default: 10000 */
    maxLength?: number;
    /** Additional patterns to redact (e.g., custom tokens) */
    redactPatterns?: RegExp[];
}
/** Safe logger interface */
interface SafeLogger {
    /** Log at specified level */
    log: (level: string, message: string, data?: unknown) => void;
    /** Log info message */
    info: (message: string, data?: unknown) => void;
    /** Log warning message */
    warn: (message: string, data?: unknown) => void;
    /** Log error message */
    error: (message: string, data?: unknown) => void;
    /** Log debug message */
    debug: (message: string, data?: unknown) => void;
}
/** Error handler configuration */
interface ErrorHandlerOptions {
    /** Show stack traces and detailed errors. Default: false */
    isDev?: boolean;
    /** Log errors. Default: true */
    logErrors?: boolean;
    /** Custom error logger */
    logger?: SafeLogger;
    /** Custom error handler */
    customHandler?: (err: Error, req: Request, res: Response) => void;
}
/** Extended Error with optional status code */
interface HttpError extends Error {
    statusCode?: number;
    status?: number;
}
/** Generic Arcis middleware type */
type ArcisMiddleware = (req: Request, res: Response, next: NextFunction) => void | Promise<void>;
/** Arcis function with attached utilities */
interface ArcisFunction {
    (options?: ArcisOptions): RequestHandler[];
    /** Clean up resources (rate limiter intervals, etc.) */
    close?: () => void;
    sanitize: (options?: SanitizeOptions) => RequestHandler;
    rateLimit: (options?: RateLimitOptions) => RateLimiterMiddleware;
    headers: (options?: HeaderOptions) => RequestHandler;
    validate: (schema: ValidationSchema, source?: 'body' | 'query' | 'params') => RequestHandler;
    logger: (options?: LogOptions) => SafeLogger;
    errorHandler: (options?: ErrorHandlerOptions | boolean) => (err: Error, req: Request, res: Response, next: NextFunction) => void;
}

export type { ArcisFunction as A, ErrorHandlerOptions as E, FieldValidator as F, HeaderOptions as H, LogOptions as L, RateLimitEntry as R, SafeLogger as S, ThreatInfo as T, ValidationConfig as V, ArcisMiddleware as a, ArcisOptions as b, HstsOptions as c, HttpError as d, RateLimitOptions as e, RateLimitResult as f, RateLimitStore as g, RateLimiterMiddleware as h, SanitizeOptions as i, SanitizeResult as j, ThreatType as k, ValidationError as l, ValidationResult as m, ValidationSchema as n };
