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
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.prototype.toString.call(value) === '[object Object]'
  );
}
