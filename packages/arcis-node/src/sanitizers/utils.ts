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
export function encodeHtmlEntities(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Checks if a value is a plain object (not null, array, Date, etc.)
 * 
 * @param value - Value to check
 * @returns True if plain object
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  // Check the actual prototype chain rather than toString, which can be spoofed
  // via Symbol.toStringTag. Accepts both Object.prototype (plain {}) and null
  // prototype objects (Object.create(null)).
  const proto = Object.getPrototypeOf(value as object);
  return proto === Object.prototype || proto === null;
}
