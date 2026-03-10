// src/core/constants.ts
var INPUT = {
  /** Default maximum input size (1MB) */
  DEFAULT_MAX_SIZE: 1e6};
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
var VALIDATION = {
  /** Email regex pattern */
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  /** URL regex pattern */
  URL: /^https?:\/\/[^\s/$.?#].[^\s]*$/,
  /** UUID regex pattern (v4) */
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
};
var ERRORS = {
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
var InputTooLargeError = class extends ArcisError {
  constructor(maxSize, actualSize) {
    super(`Input exceeds maximum size of ${maxSize} bytes`, 413, "INPUT_TOO_LARGE");
    this.name = "InputTooLargeError";
    this.maxSize = maxSize;
    this.actualSize = actualSize;
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

export { createValidator, validate };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map