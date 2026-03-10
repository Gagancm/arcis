export { c as createSanitizer, d as detectCommandInjection, a as detectNoSqlInjection, b as detectPathTraversal, e as detectPrototypePollution, f as detectSql, g as detectXss, o as getDangerousOperators, p as getDangerousProtoKeys, i as isDangerousNoSqlKey, h as isDangerousProtoKey, s as sanitizeCommand, j as sanitizeObject, k as sanitizePath, l as sanitizeSql, m as sanitizeString, n as sanitizeXss } from '../prototype-M8_3iq5e.js';
import 'express';
import '../types-D7WNLpcY.js';

/**
 * @module @arcis/node/sanitizers/utils
 * Shared utilities for sanitizers
 */
/**
 * Encodes HTML entities to prevent interpretation as markup.
 *
 * @param str - The string to encode
 * @returns The encoded string
 */
declare function encodeHtmlEntities(str: string): string;
/**
 * Checks if a value is a plain object (not null, array, Date, etc.)
 *
 * @param value - Value to check
 * @returns True if plain object
 */
declare function isPlainObject(value: unknown): value is Record<string, unknown>;

export { encodeHtmlEntities, isPlainObject };
