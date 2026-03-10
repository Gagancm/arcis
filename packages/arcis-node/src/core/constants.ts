/**
 * @module @arcis/node/core/constants
 * Named constants for Arcis - no magic numbers
 */

// =============================================================================
// INPUT LIMITS
// =============================================================================
export const INPUT = {
  /** Default maximum input size (1MB) */
  DEFAULT_MAX_SIZE: 1_000_000,
  /** Maximum recursion depth for nested objects */
  MAX_RECURSION_DEPTH: 10,
} as const;

// =============================================================================
// RATE LIMITING
// =============================================================================
export const RATE_LIMIT = {
  /** Default window size (1 minute) */
  DEFAULT_WINDOW_MS: 60_000,
  /** Default max requests per window */
  DEFAULT_MAX_REQUESTS: 100,
  /** Default HTTP status code for rate limited responses */
  DEFAULT_STATUS_CODE: 429,
  /** Default error message */
  DEFAULT_MESSAGE: 'Too many requests, please try again later.',
  /** Minimum window size (1 second) */
  MIN_WINDOW_MS: 1_000,
  /** Maximum window size (24 hours) */
  MAX_WINDOW_MS: 86_400_000,
} as const;

// =============================================================================
// SECURITY HEADERS
// =============================================================================
export const HEADERS = {
  /** Default Content Security Policy */
  DEFAULT_CSP: [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  /** Default HSTS max age (1 year in seconds) */
  HSTS_MAX_AGE: 31_536_000,
  /** Default X-Frame-Options value */
  FRAME_OPTIONS: 'DENY' as const,
  /** Default X-Content-Type-Options value */
  CONTENT_TYPE_OPTIONS: 'nosniff',
  /** Default Referrer-Policy value */
  REFERRER_POLICY: 'strict-origin-when-cross-origin',
  /** Default Permissions-Policy value */
  PERMISSIONS_POLICY: 'geolocation=(), microphone=(), camera=()',
  /** Default Cache-Control value for security */
  CACHE_CONTROL: 'no-store, no-cache, must-revalidate, proxy-revalidate',
} as const;

// =============================================================================
// XSS PATTERNS (ReDoS-safe)
// =============================================================================
export const XSS_PATTERNS = [
  /** Script tags (ReDoS-safe version) */
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /** javascript: protocol */
  /javascript:/gi,
  /** vbscript: protocol */
  /vbscript:/gi,
  /** Event handlers (onclick, onerror, etc.) */
  /on\w+\s*=/gi,
  /** iframe tags */
  /<iframe/gi,
  /** object tags */
  /<object/gi,
  /** embed tags */
  /<embed/gi,
  /** data: URIs (only dangerous ones, avoid false positives) */
  /(?:^|[\s"'=])data:/gi,
  /** URL-encoded script tags */
  /%3Cscript/gi,
  /** SVG with onload */
  /<svg[^>]*onload/gi,
] as const;

// =============================================================================
// SQL INJECTION PATTERNS
// =============================================================================
export const SQL_PATTERNS = [
  /** SQL keywords */
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b)/gi,
  /** SQL comments */
  /(--|\/\*|\*\/)/g,
  /** SQL statement separators */
  /(;|\|\||&&)/g,
  /** Boolean injection: OR 1=1 */
  /\bOR\s+\d+\s*=\s*\d+/gi,
  /** Boolean injection: OR 'a'='a' */
  /\bOR\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]/gi,
  /** Boolean injection: AND 1=1 */
  /\bAND\s+\d+\s*=\s*\d+/gi,
  /** Boolean injection: AND 'a'='a' */
  /\bAND\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]/gi,
  /** Time-based blind: SLEEP() */
  /\bSLEEP\s*\(\s*\d+\s*\)/gi,
  /** Time-based blind: BENCHMARK() */
  /\bBENCHMARK\s*\(/gi,
] as const;

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================
export const PATH_PATTERNS = [
  /** Unix path traversal */
  /\.\.\//g,
  /** Windows path traversal */
  /\.\.\\/g,
  /** URL-encoded traversal */
  /%2e%2e/gi,
  /** Double URL-encoded traversal */
  /%252e/gi,
] as const;

// =============================================================================
// COMMAND INJECTION PATTERNS
// =============================================================================
export const COMMAND_PATTERNS = [
  /** Shell metacharacters */
  /[;&|`$()]/g,
  /** Dangerous commands */
  /\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php)\b/gi,
] as const;

// =============================================================================
// DANGEROUS KEYS
// =============================================================================

/** Prototype pollution keys to block */
export const DANGEROUS_PROTO_KEYS = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

/** MongoDB operators to block */
export const NOSQL_DANGEROUS_KEYS = new Set([
  '$gt', '$gte', '$lt', '$lte', '$ne', '$eq', '$in', '$nin',
  '$and', '$or', '$not', '$exists', '$type', '$regex', '$where', '$expr',
]);

// =============================================================================
// REDACTION
// =============================================================================
export const REDACTION = {
  /** Replacement text for redacted values */
  REPLACEMENT: '[REDACTED]',
  /** Truncation indicator */
  TRUNCATED: '[TRUNCATED]',
  /** Max depth indicator */
  MAX_DEPTH: '[MAX_DEPTH]',
  /** Default max message length */
  DEFAULT_MAX_LENGTH: 10_000,
  /** Default sensitive keys to redact */
  SENSITIVE_KEYS: new Set([
    'password', 'passwd', 'pwd', 'secret', 'token', 'apikey',
    'api_key', 'apiKey', 'auth', 'authorization', 'credit_card',
    'creditcard', 'cc', 'ssn', 'social_security', 'private_key',
    'privateKey', 'access_token', 'accessToken', 'refresh_token',
    'refreshToken', 'bearer', 'jwt', 'session', 'cookie',
  ]),
} as const;

// =============================================================================
// VALIDATION PATTERNS
// =============================================================================
export const VALIDATION = {
  /** Email regex pattern */
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  /** URL regex pattern */
  URL: /^https?:\/\/[^\s/$.?#].[^\s]*$/,
  /** UUID regex pattern (v4) */
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
} as const;

// =============================================================================
// ERROR MESSAGES
// =============================================================================
export const ERRORS = {
  /** Generic error message (production) */
  INTERNAL_SERVER_ERROR: 'Internal Server Error',
  /** Input too large error */
  INPUT_TOO_LARGE: (maxSize: number) => `Input exceeds maximum size of ${maxSize} bytes`,
  /** Validation error messages */
  VALIDATION: {
    REQUIRED: (field: string) => `${field} is required`,
    INVALID_TYPE: (field: string, type: string) => `${field} must be a ${type}`,
    MIN_LENGTH: (field: string, min: number) => `${field} must be at least ${min} characters`,
    MAX_LENGTH: (field: string, max: number) => `${field} must be at most ${max} characters`,
    MIN_VALUE: (field: string, min: number) => `${field} must be at least ${min}`,
    MAX_VALUE: (field: string, max: number) => `${field} must be at most ${max}`,
    INVALID_FORMAT: (field: string) => `${field} format is invalid`,
    INVALID_EMAIL: (field: string) => `${field} must be a valid email`,
    INVALID_URL: (field: string) => `${field} must be a valid URL`,
    INVALID_UUID: (field: string) => `${field} must be a valid UUID`,
    INVALID_ENUM: (field: string, values: unknown[]) => `${field} must be one of: ${values.join(', ')}`,
    MIN_ITEMS: (field: string, min: number) => `${field} must have at least ${min} items`,
    MAX_ITEMS: (field: string, max: number) => `${field} must have at most ${max} items`,
  },
} as const;

// =============================================================================
// BLOCKED TEXT (for sanitizer replacements)
// =============================================================================
export const BLOCKED = '[BLOCKED]' as const;
