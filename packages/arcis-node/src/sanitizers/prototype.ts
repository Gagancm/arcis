/**
 * @module @arcis/node/sanitizers/prototype
 * Prototype pollution prevention
 */

import { DANGEROUS_PROTO_KEYS } from '../core/constants';

/**
 * Checks if a key is dangerous for prototype pollution.
 * Case-insensitive — catches __PROTO__, Constructor, etc.
 *
 * @param key - The key to check
 * @returns True if the key could cause prototype pollution
 *
 * @example
 * isDangerousProtoKey('__proto__')   // true
 * isDangerousProtoKey('__PROTO__')   // true
 * isDangerousProtoKey('Constructor') // true
 * isDangerousProtoKey('name')        // false
 */
export function isDangerousProtoKey(key: string): boolean {
  return DANGEROUS_PROTO_KEYS.has(key.toLowerCase());
}

/**
 * Recursively checks if an object contains prototype pollution keys.
 * 
 * @param obj - The object to check
 * @param maxDepth - Maximum recursion depth (default: 10)
 * @returns True if dangerous keys found
 */
export function detectPrototypePollution(obj: unknown, maxDepth = 10): boolean {
  if (maxDepth <= 0) return false;
  if (obj === null || typeof obj !== 'object') return false;
  
  if (Array.isArray(obj)) {
    return obj.some(item => detectPrototypePollution(item, maxDepth - 1));
  }
  
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (DANGEROUS_PROTO_KEYS.has(key.toLowerCase())) {
      return true;
    }
    
    const value = (obj as Record<string, unknown>)[key];
    if (typeof value === 'object' && value !== null) {
      if (detectPrototypePollution(value, maxDepth - 1)) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Get list of all keys considered dangerous for prototype pollution.
 * Useful for documentation or custom validation.
 * 
 * @returns Array of dangerous key strings
 */
export function getDangerousProtoKeys(): string[] {
  return Array.from(DANGEROUS_PROTO_KEYS);
}
