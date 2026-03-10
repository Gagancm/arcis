import { RequestHandler } from 'express';
import { i as SanitizeOptions, j as SanitizeResult } from './types-D7WNLpcY.js';

/**
 * @module @arcis/node/sanitizers/sanitize
 * Main sanitization functions that combine all sanitizers
 */

/**
 * Sanitize a string value against multiple attack vectors.
 *
 * @param value - The string to sanitize
 * @param options - Sanitization options
 * @returns The sanitized string
 *
 * @example
 * sanitizeString("<script>alert('xss')</script>")
 * // Returns: "&lt;alert(&#x27;xss&#x27;)&gt;"
 *
 * @example
 * sanitizeString("../../etc/passwd")
 * // Returns: "etc/passwd"
 */
declare function sanitizeString(value: string, options?: SanitizeOptions): string;
/**
 * Sanitize an object recursively, including nested objects and arrays.
 * Also removes prototype pollution and NoSQL injection keys.
 *
 * @param obj - The object to sanitize
 * @param options - Sanitization options
 * @returns The sanitized object
 */
declare function sanitizeObject(obj: unknown, options?: SanitizeOptions): unknown;
/**
 * Create Express middleware for request sanitization.
 * Sanitizes req.body, req.query, and req.params.
 *
 * @param options - Sanitization options
 * @returns Express middleware
 *
 * @example
 * app.use(createSanitizer());
 *
 * @example
 * app.use(createSanitizer({ xss: true, sql: true, nosql: true }));
 */
declare function createSanitizer(options?: SanitizeOptions): RequestHandler;

/**
 * @module @arcis/node/sanitizers/xss
 * XSS (Cross-Site Scripting) prevention
 */

/**
 * Sanitizes a string to prevent XSS attacks.
 * Removes script tags, event handlers, and dangerous URIs, then HTML-encodes.
 *
 * @param input - The string to sanitize
 * @param collectThreats - Whether to collect threat information (default: false for performance)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 *
 * @example
 * sanitizeXss("<script>alert('xss')</script>")
 * // Returns: "&lt;alert(&#x27;xss&#x27;)&gt;"
 */
declare function sanitizeXss(input: string, collectThreats?: false): string;
declare function sanitizeXss(input: string, collectThreats: true): SanitizeResult;
/**
 * Checks if a string contains potential XSS patterns.
 * Does not sanitize — use sanitizeXss() for that.
 *
 * @param input - The string to check
 * @returns True if XSS patterns detected
 */
declare function detectXss(input: string): boolean;

/**
 * @module @arcis/node/sanitizers/sql
 * SQL injection prevention
 */

/**
 * Sanitizes a string to prevent SQL injection attacks.
 * Replaces dangerous SQL patterns with [BLOCKED].
 *
 * @param input - The string to sanitize
 * @param collectThreats - Whether to collect threat information (default: false for performance)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 *
 * @example
 * sanitizeSql("'; DROP TABLE users; --")
 * // Returns: "'; [BLOCKED] TABLE users[BLOCKED] [BLOCKED]"
 */
declare function sanitizeSql(input: string, collectThreats?: false): string;
declare function sanitizeSql(input: string, collectThreats: true): SanitizeResult;
/**
 * Checks if a string contains potential SQL injection patterns.
 * Does not sanitize — use sanitizeSql() for that.
 *
 * @param input - The string to check
 * @returns True if SQL injection patterns detected
 */
declare function detectSql(input: string): boolean;

/**
 * @module @arcis/node/sanitizers/path
 * Path traversal prevention
 */

/**
 * Sanitizes a string to prevent path traversal attacks.
 * Removes ../ and ..\ patterns (including URL-encoded variants).
 *
 * @param input - The string to sanitize
 * @param collectThreats - Whether to collect threat information (default: false for performance)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 *
 * @example
 * sanitizePath("../../etc/passwd")
 * // Returns: "etc/passwd"
 */
declare function sanitizePath(input: string, collectThreats?: false): string;
declare function sanitizePath(input: string, collectThreats: true): SanitizeResult;
/**
 * Checks if a string contains path traversal patterns.
 * Does not sanitize — use sanitizePath() for that.
 *
 * @param input - The string to check
 * @returns True if path traversal patterns detected
 */
declare function detectPathTraversal(input: string): boolean;

/**
 * @module @arcis/node/sanitizers/command
 * Command injection prevention
 */

/**
 * Sanitizes a string to prevent command injection attacks.
 * Replaces shell metacharacters and dangerous commands with [BLOCKED].
 *
 * @param input - The string to sanitize
 * @param collectThreats - Whether to collect threat information (default: false for performance)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 *
 * @example
 * sanitizeCommand("file.txt; rm -rf /")
 * // Returns: "file.txt[BLOCKED] [BLOCKED] -rf /"
 */
declare function sanitizeCommand(input: string, collectThreats?: false): string;
declare function sanitizeCommand(input: string, collectThreats: true): SanitizeResult;
/**
 * Checks if a string contains command injection patterns.
 * Does not sanitize — use sanitizeCommand() for that.
 *
 * @param input - The string to check
 * @returns True if command injection patterns detected
 */
declare function detectCommandInjection(input: string): boolean;

/**
 * @module @arcis/node/sanitizers/nosql
 * NoSQL injection prevention (MongoDB operators)
 */
/**
 * Checks if a key is a dangerous MongoDB operator.
 *
 * @param key - The key to check
 * @returns True if the key is a MongoDB operator
 *
 * @example
 * isDangerousNoSqlKey('$gt') // true
 * isDangerousNoSqlKey('name') // false
 */
declare function isDangerousNoSqlKey(key: string): boolean;
/**
 * Recursively checks if an object contains dangerous MongoDB operators.
 *
 * @param obj - The object to check
 * @param maxDepth - Maximum recursion depth (default: 10)
 * @returns True if dangerous operators found
 */
declare function detectNoSqlInjection(obj: unknown, maxDepth?: number): boolean;
/**
 * Get list of all MongoDB operators considered dangerous.
 * Useful for documentation or custom validation.
 *
 * @returns Array of dangerous operator strings
 */
declare function getDangerousOperators(): string[];

/**
 * @module @arcis/node/sanitizers/prototype
 * Prototype pollution prevention
 */
/**
 * Checks if a key is dangerous for prototype pollution.
 *
 * @param key - The key to check
 * @returns True if the key could cause prototype pollution
 *
 * @example
 * isDangerousProtoKey('__proto__') // true
 * isDangerousProtoKey('name') // false
 */
declare function isDangerousProtoKey(key: string): boolean;
/**
 * Recursively checks if an object contains prototype pollution keys.
 *
 * @param obj - The object to check
 * @param maxDepth - Maximum recursion depth (default: 10)
 * @returns True if dangerous keys found
 */
declare function detectPrototypePollution(obj: unknown, maxDepth?: number): boolean;
/**
 * Get list of all keys considered dangerous for prototype pollution.
 * Useful for documentation or custom validation.
 *
 * @returns Array of dangerous key strings
 */
declare function getDangerousProtoKeys(): string[];

export { detectNoSqlInjection as a, detectPathTraversal as b, createSanitizer as c, detectCommandInjection as d, detectPrototypePollution as e, detectSql as f, detectXss as g, isDangerousProtoKey as h, isDangerousNoSqlKey as i, sanitizeObject as j, sanitizePath as k, sanitizeSql as l, sanitizeString as m, sanitizeXss as n, getDangerousOperators as o, getDangerousProtoKeys as p, sanitizeCommand as s };
