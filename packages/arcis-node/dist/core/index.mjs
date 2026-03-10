// src/core/constants.ts
var INPUT = {
  /** Default maximum input size (1MB) */
  DEFAULT_MAX_SIZE: 1e6,
  /** Maximum recursion depth for nested objects */
  MAX_RECURSION_DEPTH: 10
};
var RATE_LIMIT = {
  /** Default window size (1 minute) */
  DEFAULT_WINDOW_MS: 6e4,
  /** Default max requests per window */
  DEFAULT_MAX_REQUESTS: 100,
  /** Default HTTP status code for rate limited responses */
  DEFAULT_STATUS_CODE: 429,
  /** Default error message */
  DEFAULT_MESSAGE: "Too many requests, please try again later.",
  /** Minimum window size (1 second) */
  MIN_WINDOW_MS: 1e3,
  /** Maximum window size (24 hours) */
  MAX_WINDOW_MS: 864e5
};
var HEADERS = {
  /** Default Content Security Policy */
  DEFAULT_CSP: [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'"
  ].join("; "),
  /** Default HSTS max age (1 year in seconds) */
  HSTS_MAX_AGE: 31536e3,
  /** Default X-Frame-Options value */
  FRAME_OPTIONS: "DENY",
  /** Default X-Content-Type-Options value */
  CONTENT_TYPE_OPTIONS: "nosniff",
  /** Default Referrer-Policy value */
  REFERRER_POLICY: "strict-origin-when-cross-origin",
  /** Default Permissions-Policy value */
  PERMISSIONS_POLICY: "geolocation=(), microphone=(), camera=()",
  /** Default Cache-Control value for security */
  CACHE_CONTROL: "no-store, no-cache, must-revalidate, proxy-revalidate"
};
var XSS_PATTERNS = [
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
  /<svg[^>]*onload/gi
];
var SQL_PATTERNS = [
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
  /\bBENCHMARK\s*\(/gi
];
var PATH_PATTERNS = [
  /** Unix path traversal */
  /\.\.\//g,
  /** Windows path traversal */
  /\.\.\\/g,
  /** URL-encoded traversal */
  /%2e%2e/gi,
  /** Double URL-encoded traversal */
  /%252e/gi
];
var COMMAND_PATTERNS = [
  /** Shell metacharacters */
  /[;&|`$()]/g,
  /** Dangerous commands */
  /\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php)\b/gi
];
var DANGEROUS_PROTO_KEYS = /* @__PURE__ */ new Set([
  "__proto__",
  "constructor",
  "prototype"
]);
var NOSQL_DANGEROUS_KEYS = /* @__PURE__ */ new Set([
  "$gt",
  "$gte",
  "$lt",
  "$lte",
  "$ne",
  "$eq",
  "$in",
  "$nin",
  "$and",
  "$or",
  "$not",
  "$exists",
  "$type",
  "$regex",
  "$where",
  "$expr"
]);
var REDACTION = {
  /** Replacement text for redacted values */
  REPLACEMENT: "[REDACTED]",
  /** Truncation indicator */
  TRUNCATED: "[TRUNCATED]",
  /** Max depth indicator */
  MAX_DEPTH: "[MAX_DEPTH]",
  /** Default max message length */
  DEFAULT_MAX_LENGTH: 1e4,
  /** Default sensitive keys to redact */
  SENSITIVE_KEYS: /* @__PURE__ */ new Set([
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "apiKey",
    "auth",
    "authorization",
    "credit_card",
    "creditcard",
    "cc",
    "ssn",
    "social_security",
    "private_key",
    "privateKey",
    "access_token",
    "accessToken",
    "refresh_token",
    "refreshToken",
    "bearer",
    "jwt",
    "session",
    "cookie"
  ])
};
var VALIDATION = {
  /** Email regex pattern */
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  /** URL regex pattern */
  URL: /^https?:\/\/[^\s/$.?#].[^\s]*$/,
  /** UUID regex pattern (v4) */
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
};
var ERRORS = {
  /** Generic error message (production) */
  INTERNAL_SERVER_ERROR: "Internal Server Error",
  /** Input too large error */
  INPUT_TOO_LARGE: (maxSize) => `Input exceeds maximum size of ${maxSize} bytes`,
  /** Validation error messages */
  VALIDATION: {
    REQUIRED: (field) => `${field} is required`,
    INVALID_TYPE: (field, type) => `${field} must be a ${type}`,
    MIN_LENGTH: (field, min) => `${field} must be at least ${min} characters`,
    MAX_LENGTH: (field, max) => `${field} must be at most ${max} characters`,
    MIN_VALUE: (field, min) => `${field} must be at least ${min}`,
    MAX_VALUE: (field, max) => `${field} must be at most ${max}`,
    INVALID_FORMAT: (field) => `${field} format is invalid`,
    INVALID_EMAIL: (field) => `${field} must be a valid email`,
    INVALID_URL: (field) => `${field} must be a valid URL`,
    INVALID_UUID: (field) => `${field} must be a valid UUID`,
    INVALID_ENUM: (field, values) => `${field} must be one of: ${values.join(", ")}`,
    MIN_ITEMS: (field, min) => `${field} must have at least ${min} items`,
    MAX_ITEMS: (field, max) => `${field} must have at most ${max} items`
  }
};
var BLOCKED = "[BLOCKED]";

// src/core/errors.ts
var ArcisError = class extends Error {
  constructor(message, statusCode = 500, code = "ARCIS_ERROR") {
    super(message);
    this.name = "ArcisError";
    this.statusCode = statusCode;
    this.code = code;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
};
var ValidationError = class extends ArcisError {
  constructor(errors) {
    super("Validation failed", 400, "VALIDATION_ERROR");
    this.name = "ValidationError";
    this.errors = errors;
  }
};
var RateLimitError = class extends ArcisError {
  constructor(message, retryAfter) {
    super(message, 429, "RATE_LIMIT_EXCEEDED");
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
};
var InputTooLargeError = class extends ArcisError {
  constructor(maxSize, actualSize) {
    super(`Input exceeds maximum size of ${maxSize} bytes`, 413, "INPUT_TOO_LARGE");
    this.name = "InputTooLargeError";
    this.maxSize = maxSize;
    this.actualSize = actualSize;
  }
};
var SecurityThreatError = class extends ArcisError {
  constructor(threatType, pattern) {
    super("Request blocked for security reasons", 400, "SECURITY_THREAT");
    this.name = "SecurityThreatError";
    this.threatType = threatType;
    this.pattern = pattern;
  }
};
var SanitizationError = class extends ArcisError {
  constructor(message) {
    super(message, 400, "SANITIZATION_ERROR");
    this.name = "SanitizationError";
  }
};

export { ArcisError, ValidationError as ArcisValidationError, BLOCKED, COMMAND_PATTERNS, DANGEROUS_PROTO_KEYS, ERRORS, HEADERS, INPUT, InputTooLargeError, NOSQL_DANGEROUS_KEYS, PATH_PATTERNS, RATE_LIMIT, REDACTION, RateLimitError, SQL_PATTERNS, SanitizationError, SecurityThreatError, VALIDATION, XSS_PATTERNS };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map