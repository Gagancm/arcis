'use strict';

// src/core/constants.ts
var INPUT = {
  /** Maximum recursion depth for nested objects */
  MAX_RECURSION_DEPTH: 10
};
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

exports.createRedactor = createRedactor;
exports.createSafeLogger = createSafeLogger;
exports.safeLog = safeLog;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map