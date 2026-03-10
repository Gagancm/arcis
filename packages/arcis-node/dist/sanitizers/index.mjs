// src/core/constants.ts
var INPUT = {
  /** Default maximum input size (1MB) */
  DEFAULT_MAX_SIZE: 1e6,
  /** Maximum recursion depth for nested objects */
  MAX_RECURSION_DEPTH: 10
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
function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.prototype.toString.call(value) === "[object Object]";
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
function getDangerousOperators() {
  return Array.from(NOSQL_DANGEROUS_KEYS);
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
function getDangerousProtoKeys() {
  return Array.from(DANGEROUS_PROTO_KEYS);
}

export { createSanitizer, detectCommandInjection, detectNoSqlInjection, detectPathTraversal, detectPrototypePollution, detectSql, detectXss, encodeHtmlEntities, getDangerousOperators, getDangerousProtoKeys, isDangerousNoSqlKey, isDangerousProtoKey, isPlainObject, sanitizeCommand, sanitizeObject, sanitizePath, sanitizeSql, sanitizeString, sanitizeXss };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map