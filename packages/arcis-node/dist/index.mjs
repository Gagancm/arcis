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

// src/middleware/headers.ts
function createHeaders(options = {}) {
  const {
    contentSecurityPolicy = true,
    xssFilter = true,
    noSniff = true,
    frameOptions = HEADERS.FRAME_OPTIONS,
    hsts = true,
    referrerPolicy = HEADERS.REFERRER_POLICY,
    permissionsPolicy = HEADERS.PERMISSIONS_POLICY,
    cacheControl = true
  } = options;
  return (_req, res, next) => {
    if (contentSecurityPolicy) {
      const csp = typeof contentSecurityPolicy === "string" ? contentSecurityPolicy : HEADERS.DEFAULT_CSP;
      res.setHeader("Content-Security-Policy", csp);
    }
    if (xssFilter) {
      res.setHeader("X-XSS-Protection", "1; mode=block");
    }
    if (noSniff) {
      res.setHeader("X-Content-Type-Options", HEADERS.CONTENT_TYPE_OPTIONS);
    }
    if (frameOptions) {
      res.setHeader("X-Frame-Options", frameOptions);
    }
    if (hsts) {
      const hstsOpts = typeof hsts === "object" ? hsts : {};
      const maxAge = hstsOpts.maxAge ?? HEADERS.HSTS_MAX_AGE;
      const includeSubDomains = hstsOpts.includeSubDomains !== false;
      const preload = hstsOpts.preload === true;
      let hstsValue = `max-age=${maxAge}`;
      if (includeSubDomains) hstsValue += "; includeSubDomains";
      if (preload) hstsValue += "; preload";
      res.setHeader("Strict-Transport-Security", hstsValue);
    }
    if (referrerPolicy) {
      res.setHeader("Referrer-Policy", referrerPolicy);
    }
    if (permissionsPolicy) {
      res.setHeader("Permissions-Policy", permissionsPolicy);
    }
    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
    if (cacheControl) {
      const cacheControlValue = typeof cacheControl === "string" ? cacheControl : HEADERS.CACHE_CONTROL;
      res.setHeader("Cache-Control", cacheControlValue);
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
    }
    res.removeHeader("X-Powered-By");
    next();
  };
}
var securityHeaders = createHeaders;

// src/middleware/rate-limit.ts
function createRateLimiter(options = {}) {
  const {
    max = RATE_LIMIT.DEFAULT_MAX_REQUESTS,
    windowMs = RATE_LIMIT.DEFAULT_WINDOW_MS,
    message = RATE_LIMIT.DEFAULT_MESSAGE,
    statusCode = RATE_LIMIT.DEFAULT_STATUS_CODE,
    keyGenerator = (req) => req.ip || req.socket?.remoteAddress || "unknown",
    skip,
    store: externalStore
  } = options;
  const inMemoryStore = {};
  let cleanupInterval = null;
  if (!externalStore) {
    cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const key of Object.keys(inMemoryStore)) {
        if (inMemoryStore[key].resetTime < now) {
          delete inMemoryStore[key];
        }
      }
    }, windowMs);
    if (typeof cleanupInterval.unref === "function") {
      cleanupInterval.unref();
    }
  }
  const handler = async (req, res, next) => {
    try {
      if (skip?.(req)) {
        return next();
      }
      const key = keyGenerator(req);
      const now = Date.now();
      let count;
      let resetTime;
      if (externalStore) {
        const entry = await externalStore.get(key);
        if (!entry || entry.resetTime < now) {
          await externalStore.set(key, { count: 1, resetTime: now + windowMs });
          count = 1;
          resetTime = now + windowMs;
        } else {
          count = await externalStore.increment(key);
          resetTime = entry.resetTime;
        }
      } else {
        if (!inMemoryStore[key] || inMemoryStore[key].resetTime < now) {
          inMemoryStore[key] = { count: 1, resetTime: now + windowMs };
        } else {
          inMemoryStore[key].count++;
        }
        count = inMemoryStore[key].count;
        resetTime = inMemoryStore[key].resetTime;
      }
      const remaining = Math.max(0, max - count);
      const resetSeconds = Math.ceil((resetTime - now) / 1e3);
      res.setHeader("X-RateLimit-Limit", max.toString());
      res.setHeader("X-RateLimit-Remaining", remaining.toString());
      res.setHeader("X-RateLimit-Reset", resetSeconds.toString());
      if (count > max) {
        res.setHeader("Retry-After", resetSeconds.toString());
        res.status(statusCode).json({
          error: message,
          retryAfter: resetSeconds
        });
        return;
      }
      next();
    } catch (error) {
      console.error("[arcis] Rate limiter error:", error);
      next();
    }
  };
  const middleware = handler;
  middleware.close = () => {
    if (cleanupInterval) {
      clearInterval(cleanupInterval);
      cleanupInterval = null;
    }
  };
  return middleware;
}
var rateLimit = createRateLimiter;

// src/middleware/error-handler.ts
function errorHandler(options = false) {
  const isDev = typeof options === "boolean" ? options : options.isDev ?? false;
  const logErrors = typeof options === "object" ? options.logErrors ?? true : true;
  const logger = typeof options === "object" ? options.logger : void 0;
  const customHandler = typeof options === "object" ? options.customHandler : void 0;
  return (err, req, res, _next) => {
    const statusCode = err.statusCode || err.status || 500;
    if (customHandler) {
      return customHandler(err, req, res);
    }
    if (logErrors) {
      const logData = {
        error: err.message,
        stack: err.stack,
        statusCode,
        path: req.path,
        method: req.method
      };
      if (logger) {
        logger.error("Request error", logData);
      } else {
        console.error("[arcis] Request error:", logData);
      }
    }
    const response = {
      error: statusCode >= 500 ? ERRORS.INTERNAL_SERVER_ERROR : err.message
    };
    if (isDev) {
      response.stack = err.stack;
      response.details = err.message;
    }
    res.status(statusCode).json(response);
  };
}
var createErrorHandler = errorHandler;

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

// src/sanitizers/utils.ts
function encodeHtmlEntities(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

// src/sanitizers/xss.ts
function sanitizeXss(input, collectThreats = false) {
  if (typeof input !== "string") {
    return collectThreats ? { value: String(input), wasSanitized: false, threats: [] } : String(input);
  }
  const threats = [];
  let value = input;
  let wasSanitized = false;
  for (const pattern of XSS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: "xss",
              pattern: pattern.source,
              original: match
            });
          }
        }
      }
      value = value.replace(pattern, "");
      wasSanitized = true;
    }
  }
  const encoded = encodeHtmlEntities(value);
  if (encoded !== value) {
    wasSanitized = true;
  }
  value = encoded;
  if (collectThreats) {
    return { value, wasSanitized, threats };
  }
  return value;
}
function detectXss(input) {
  if (typeof input !== "string") return false;
  for (const pattern of XSS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }
  return false;
}

// src/sanitizers/sql.ts
function sanitizeSql(input, collectThreats = false) {
  if (typeof input !== "string") {
    return collectThreats ? { value: String(input), wasSanitized: false, threats: [] } : String(input);
  }
  const threats = [];
  let value = input;
  let wasSanitized = false;
  for (const pattern of SQL_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: "sql_injection",
              pattern: pattern.source,
              original: match
            });
          }
        }
      }
      value = value.replace(pattern, BLOCKED);
      wasSanitized = true;
    }
  }
  if (collectThreats) {
    return { value, wasSanitized, threats };
  }
  return value;
}
function detectSql(input) {
  if (typeof input !== "string") return false;
  for (const pattern of SQL_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }
  return false;
}

// src/sanitizers/path.ts
function sanitizePath(input, collectThreats = false) {
  if (typeof input !== "string") {
    return collectThreats ? { value: String(input), wasSanitized: false, threats: [] } : String(input);
  }
  const threats = [];
  let value = input;
  let wasSanitized = false;
  for (const pattern of PATH_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: "path_traversal",
              pattern: pattern.source,
              original: match
            });
          }
        }
      }
      value = value.replace(pattern, "");
      wasSanitized = true;
    }
  }
  if (collectThreats) {
    return { value, wasSanitized, threats };
  }
  return value;
}
function detectPathTraversal(input) {
  if (typeof input !== "string") return false;
  for (const pattern of PATH_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }
  return false;
}

// src/sanitizers/command.ts
function sanitizeCommand(input, collectThreats = false) {
  if (typeof input !== "string") {
    return collectThreats ? { value: String(input), wasSanitized: false, threats: [] } : String(input);
  }
  const threats = [];
  let value = input;
  let wasSanitized = false;
  for (const pattern of COMMAND_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: "command_injection",
              pattern: pattern.source,
              original: match
            });
          }
        }
      }
      value = value.replace(pattern, BLOCKED);
      wasSanitized = true;
    }
  }
  if (collectThreats) {
    return { value, wasSanitized, threats };
  }
  return value;
}
function detectCommandInjection(input) {
  if (typeof input !== "string") return false;
  for (const pattern of COMMAND_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }
  return false;
}

// src/sanitizers/sanitize.ts
function sanitizeString(value, options = {}) {
  if (typeof value !== "string") return value;
  const maxSize = options.maxSize ?? INPUT.DEFAULT_MAX_SIZE;
  if (value.length > maxSize) {
    throw new InputTooLargeError(maxSize, value.length);
  }
  let result = value;
  if (options.xss !== false) {
    result = sanitizeXss(result);
  }
  if (options.sql !== false) {
    result = sanitizeSql(result);
  }
  if (options.path !== false) {
    result = sanitizePath(result);
  }
  if (options.command !== false) {
    result = sanitizeCommand(result);
  }
  return result;
}
function sanitizeObject(obj, options = {}) {
  if (obj === null || obj === void 0) return obj;
  if (typeof obj === "string") return sanitizeString(obj, options);
  if (typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map((item) => sanitizeObject(item, options));
  return sanitizeObjectDepth(obj, options, 0);
}
function sanitizeObjectDepth(obj, options, depth) {
  if (depth > INPUT.MAX_RECURSION_DEPTH) return obj;
  const result = {};
  for (const key of Object.keys(obj)) {
    if (options.proto !== false && DANGEROUS_PROTO_KEYS.has(key)) {
      continue;
    }
    if (options.nosql !== false && NOSQL_DANGEROUS_KEYS.has(key)) {
      continue;
    }
    const sanitizedKey = sanitizeXss(key);
    const value = obj[key];
    if (value === null || value === void 0) {
      result[sanitizedKey] = value;
    } else if (typeof value === "string") {
      result[sanitizedKey] = sanitizeString(value, options);
    } else if (Array.isArray(value)) {
      result[sanitizedKey] = value.map((item) => sanitizeObject(item, options));
    } else if (typeof value === "object") {
      result[sanitizedKey] = sanitizeObjectDepth(value, options, depth + 1);
    } else {
      result[sanitizedKey] = value;
    }
  }
  return result;
}
function createSanitizer(options = {}) {
  return (req, _res, next) => {
    try {
      if (req.body && typeof req.body === "object") {
        req.body = sanitizeObject(req.body, options);
      }
      if (req.query && typeof req.query === "object") {
        req.query = sanitizeObject(req.query, options);
      }
      if (req.params && typeof req.params === "object") {
        req.params = sanitizeObject(req.params, options);
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

// src/sanitizers/nosql.ts
function isDangerousNoSqlKey(key) {
  return NOSQL_DANGEROUS_KEYS.has(key);
}
function detectNoSqlInjection(obj, maxDepth = 10) {
  if (maxDepth <= 0) return false;
  if (obj === null || typeof obj !== "object") return false;
  if (Array.isArray(obj)) {
    return obj.some((item) => detectNoSqlInjection(item, maxDepth - 1));
  }
  for (const key of Object.keys(obj)) {
    if (isDangerousNoSqlKey(key)) {
      return true;
    }
    const value = obj[key];
    if (typeof value === "object" && value !== null) {
      if (detectNoSqlInjection(value, maxDepth - 1)) {
        return true;
      }
    }
  }
  return false;
}

// src/sanitizers/prototype.ts
function isDangerousProtoKey(key) {
  return DANGEROUS_PROTO_KEYS.has(key);
}
function detectPrototypePollution(obj, maxDepth = 10) {
  if (maxDepth <= 0) return false;
  if (obj === null || typeof obj !== "object") return false;
  if (Array.isArray(obj)) {
    return obj.some((item) => detectPrototypePollution(item, maxDepth - 1));
  }
  for (const key of Object.keys(obj)) {
    if (isDangerousProtoKey(key)) {
      return true;
    }
    const value = obj[key];
    if (typeof value === "object" && value !== null) {
      if (detectPrototypePollution(value, maxDepth - 1)) {
        return true;
      }
    }
  }
  return false;
}

// src/validation/schema.ts
function validate(schema, source = "body") {
  return (req, res, next) => {
    const data = req[source] || {};
    const errors = [];
    const validated = {};
    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];
      const result = validateField(field, value, rules);
      if (result.errors.length > 0) {
        errors.push(...result.errors);
      } else if (result.value !== void 0) {
        validated[field] = result.value;
      }
    }
    if (errors.length > 0) {
      res.status(400).json({ errors });
      return;
    }
    req[source] = validated;
    next();
  };
}
function validateField(field, value, rules) {
  const errors = [];
  if (rules.required && (value === void 0 || value === null || value === "")) {
    errors.push(ERRORS.VALIDATION.REQUIRED(field));
    return { errors };
  }
  if (value === void 0 || value === null) {
    return { errors: [] };
  }
  let typedValue = value;
  let isValid = true;
  switch (rules.type) {
    case "string":
      if (typeof value !== "string") {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, "string"));
        isValid = false;
        break;
      }
      if (rules.min !== void 0 && value.length < rules.min) {
        errors.push(ERRORS.VALIDATION.MIN_LENGTH(field, rules.min));
        isValid = false;
      }
      if (rules.max !== void 0 && value.length > rules.max) {
        errors.push(ERRORS.VALIDATION.MAX_LENGTH(field, rules.max));
        isValid = false;
      }
      if (rules.pattern && !rules.pattern.test(value)) {
        errors.push(ERRORS.VALIDATION.INVALID_FORMAT(field));
        isValid = false;
      }
      if (isValid && rules.sanitize !== false) {
        typedValue = sanitizeString(value);
      }
      break;
    case "number":
      typedValue = Number(value);
      if (isNaN(typedValue)) {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, "number"));
        isValid = false;
        break;
      }
      if (rules.min !== void 0 && typedValue < rules.min) {
        errors.push(ERRORS.VALIDATION.MIN_VALUE(field, rules.min));
        isValid = false;
      }
      if (rules.max !== void 0 && typedValue > rules.max) {
        errors.push(ERRORS.VALIDATION.MAX_VALUE(field, rules.max));
        isValid = false;
      }
      break;
    case "boolean":
      if (value === "true" || value === true || value === 1 || value === "1") {
        typedValue = true;
      } else if (value === "false" || value === false || value === 0 || value === "0") {
        typedValue = false;
      } else {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, "boolean"));
        isValid = false;
      }
      break;
    case "email":
      if (!VALIDATION.EMAIL.test(String(value))) {
        errors.push(ERRORS.VALIDATION.INVALID_EMAIL(field));
        isValid = false;
      }
      if (isValid) {
        typedValue = sanitizeString(String(value).toLowerCase().trim());
      }
      break;
    case "url":
      if (!VALIDATION.URL.test(String(value))) {
        errors.push(ERRORS.VALIDATION.INVALID_URL(field));
        isValid = false;
      }
      if (isValid) {
        typedValue = sanitizeString(String(value));
      }
      break;
    case "uuid":
      if (!VALIDATION.UUID.test(String(value))) {
        errors.push(ERRORS.VALIDATION.INVALID_UUID(field));
        isValid = false;
      }
      break;
    case "array":
      if (!Array.isArray(value)) {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, "array"));
        isValid = false;
        break;
      }
      if (rules.min !== void 0 && value.length < rules.min) {
        errors.push(ERRORS.VALIDATION.MIN_ITEMS(field, rules.min));
        isValid = false;
      }
      if (rules.max !== void 0 && value.length > rules.max) {
        errors.push(ERRORS.VALIDATION.MAX_ITEMS(field, rules.max));
        isValid = false;
      }
      break;
    case "object":
      if (typeof value !== "object" || Array.isArray(value) || value === null) {
        errors.push(ERRORS.VALIDATION.INVALID_TYPE(field, "object"));
        isValid = false;
      }
      break;
  }
  if (isValid && rules.enum && !rules.enum.includes(typedValue)) {
    errors.push(ERRORS.VALIDATION.INVALID_ENUM(field, rules.enum));
    isValid = false;
  }
  if (isValid && rules.custom) {
    const customResult = rules.custom(typedValue);
    if (customResult !== true) {
      errors.push(typeof customResult === "string" ? customResult : `${field} is invalid`);
      isValid = false;
    }
  }
  return {
    value: isValid ? typedValue : void 0,
    errors
  };
}
var createValidator = validate;

// src/logging/redactor.ts
function createSafeLogger(options = {}) {
  const {
    redactKeys = [],
    maxLength = REDACTION.DEFAULT_MAX_LENGTH,
    redactPatterns = []
  } = options;
  const allRedactKeys = /* @__PURE__ */ new Set([
    ...Array.from(REDACTION.SENSITIVE_KEYS),
    ...redactKeys.map((k) => k.toLowerCase())
  ]);
  function redact(obj, depth = 0) {
    if (depth > INPUT.MAX_RECURSION_DEPTH) return REDACTION.MAX_DEPTH;
    if (obj === null || obj === void 0) return obj;
    if (typeof obj === "string") {
      return redactString(obj, maxLength, redactPatterns);
    }
    if (typeof obj !== "object") return obj;
    if (Array.isArray(obj)) {
      return obj.map((item) => redact(item, depth + 1));
    }
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      if (allRedactKeys.has(key.toLowerCase())) {
        result[key] = REDACTION.REPLACEMENT;
      } else {
        result[key] = redact(value, depth + 1);
      }
    }
    return result;
  }
  function log(level, message, data) {
    const entry = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      level,
      message: redactString(message, maxLength, redactPatterns)
    };
    if (data !== void 0) {
      entry.data = redact(data);
    }
    console.log(JSON.stringify(entry));
  }
  return {
    log,
    info: (msg, data) => log("info", msg, data),
    warn: (msg, data) => log("warn", msg, data),
    error: (msg, data) => log("error", msg, data),
    debug: (msg, data) => log("debug", msg, data)
  };
}
function redactString(str, maxLength, patterns) {
  let safe = str.replace(/[\r\n\t]/g, " ").replace(/[^\x20-\x7E\u00A0-\u024F]/g, "");
  for (const pattern of patterns) {
    safe = safe.replace(pattern, REDACTION.REPLACEMENT);
  }
  if (safe.length > maxLength) {
    safe = safe.substring(0, maxLength) + `...${REDACTION.TRUNCATED}`;
  }
  return safe;
}
function createRedactor(sensitiveKeys = []) {
  const allKeys = /* @__PURE__ */ new Set([
    ...Array.from(REDACTION.SENSITIVE_KEYS),
    ...sensitiveKeys.map((k) => k.toLowerCase())
  ]);
  function redact(obj, depth = 0) {
    if (depth > INPUT.MAX_RECURSION_DEPTH) return REDACTION.MAX_DEPTH;
    if (obj === null || obj === void 0) return obj;
    if (typeof obj !== "object") return obj;
    if (Array.isArray(obj)) {
      return obj.map((item) => redact(item, depth + 1));
    }
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
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
var safeLog = createSafeLogger;

// src/middleware/main.ts
function arcis(options = {}) {
  const middlewares = [];
  const cleanupFns = [];
  if (options.headers !== false) {
    const headerOpts = typeof options.headers === "object" ? options.headers : {};
    middlewares.push(createHeaders(headerOpts));
  }
  if (options.rateLimit !== false) {
    const rateLimitOpts = typeof options.rateLimit === "object" ? options.rateLimit : {};
    const rateLimiter = createRateLimiter(rateLimitOpts);
    middlewares.push(rateLimiter);
    cleanupFns.push(() => rateLimiter.close());
  }
  if (options.sanitize !== false) {
    const sanitizeOpts = typeof options.sanitize === "object" ? options.sanitize : {};
    middlewares.push(createSanitizer(sanitizeOpts));
  }
  const result = middlewares;
  result.close = () => {
    for (const fn of cleanupFns) {
      fn();
    }
  };
  return result;
}
var arcisWithMethods = arcis;
arcisWithMethods.sanitize = createSanitizer;
arcisWithMethods.rateLimit = createRateLimiter;
arcisWithMethods.headers = createHeaders;
arcisWithMethods.validate = validate;
arcisWithMethods.logger = createSafeLogger;
arcisWithMethods.errorHandler = createErrorHandler;
var main_default = arcisWithMethods;

// src/stores/memory.ts
var MemoryStore = class {
  constructor(windowMs = RATE_LIMIT.DEFAULT_WINDOW_MS) {
    this.store = /* @__PURE__ */ new Map();
    this.cleanupInterval = null;
    this.windowMs = windowMs;
    this.startCleanup();
  }
  /**
   * Start the cleanup interval to remove expired entries.
   */
  startCleanup() {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.store.entries()) {
        if (entry.resetTime < now) {
          this.store.delete(key);
        }
      }
    }, this.windowMs);
    if (typeof this.cleanupInterval.unref === "function") {
      this.cleanupInterval.unref();
    }
  }
  async get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.resetTime < Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry;
  }
  async set(key, entry) {
    this.store.set(key, entry);
  }
  async increment(key) {
    const now = Date.now();
    const entry = this.store.get(key);
    if (!entry || entry.resetTime < now) {
      this.store.set(key, { count: 1, resetTime: now + this.windowMs });
      return 1;
    }
    entry.count++;
    return entry.count;
  }
  async decrement(key) {
    const entry = this.store.get(key);
    if (entry && entry.count > 0) {
      entry.count--;
    }
  }
  async reset(key) {
    this.store.delete(key);
  }
  async close() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }
  /**
   * Get current store size (for monitoring).
   */
  get size() {
    return this.store.size;
  }
};

// src/stores/redis.ts
var RedisStore = class {
  constructor(options) {
    this.client = options.client;
    this.prefix = options.prefix ?? "arcis:rl:";
    this.windowMs = options.windowMs ?? RATE_LIMIT.DEFAULT_WINDOW_MS;
    this.windowSec = Math.ceil(this.windowMs / 1e3);
  }
  getKey(key) {
    return `${this.prefix}${key}`;
  }
  async get(key) {
    const redisKey = this.getKey(key);
    const [countStr, ttl] = await Promise.all([
      this.client.get(redisKey),
      this.client.ttl(redisKey)
    ]);
    if (!countStr || ttl < 0) {
      return null;
    }
    return {
      count: parseInt(countStr, 10),
      resetTime: Date.now() + ttl * 1e3
    };
  }
  async set(key, entry) {
    const redisKey = this.getKey(key);
    const ttlSec = Math.ceil((entry.resetTime - Date.now()) / 1e3);
    if (ttlSec > 0) {
      await this.client.setex(redisKey, ttlSec, entry.count.toString());
    }
  }
  async increment(key) {
    const redisKey = this.getKey(key);
    const count = await this.client.incr(redisKey);
    if (count === 1) {
      await this.client.set(redisKey, count.toString(), "EX", this.windowSec);
    }
    return count;
  }
  async decrement(key) {
    const redisKey = this.getKey(key);
    await this.client.decr(redisKey);
  }
  async reset(key) {
    const redisKey = this.getKey(key);
    await this.client.del(redisKey);
  }
  async close() {
  }
};
function createRedisStore(options) {
  return new RedisStore(options);
}

export { ArcisError, ValidationError as ArcisValidationError, BLOCKED, ERRORS, HEADERS, INPUT, InputTooLargeError, MemoryStore, RATE_LIMIT, REDACTION, RateLimitError, RedisStore, SanitizationError, SecurityThreatError, VALIDATION, arcis, arcisWithMethods as arcisFunction, createErrorHandler, createHeaders, createRateLimiter, createRedactor, createRedisStore, createSafeLogger, createSanitizer, createValidator, main_default as default, detectCommandInjection, detectNoSqlInjection, detectPathTraversal, detectPrototypePollution, detectSql, detectXss, errorHandler, isDangerousNoSqlKey, isDangerousProtoKey, rateLimit, safeLog, sanitizeCommand, sanitizeObject, sanitizePath, sanitizeSql, sanitizeString, sanitizeXss, securityHeaders, validate };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map