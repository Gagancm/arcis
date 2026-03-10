/**
 * @module @arcis/node/sanitizers/sql
 * SQL injection prevention
 */

import { SQL_PATTERNS, BLOCKED } from '../core/constants';
import type { SanitizeResult, ThreatInfo } from '../core/types';

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
export function sanitizeSql(input: string, collectThreats?: false): string;
export function sanitizeSql(input: string, collectThreats: true): SanitizeResult;
export function sanitizeSql(input: string, collectThreats = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats 
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let value = input;
  let wasSanitized = false;

  for (const pattern of SQL_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.lastIndex = 0;
    
    if (pattern.test(value)) {
      pattern.lastIndex = 0; // Reset again for replace
      
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: 'sql_injection',
              pattern: pattern.source,
              original: match,
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

/**
 * Checks if a string contains potential SQL injection patterns.
 * Does not sanitize — use sanitizeSql() for that.
 * 
 * @param input - The string to check
 * @returns True if SQL injection patterns detected
 */
export function detectSql(input: string): boolean {
  if (typeof input !== 'string') return false;
  
  for (const pattern of SQL_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }
  
  return false;
}
