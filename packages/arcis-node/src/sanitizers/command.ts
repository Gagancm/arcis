/**
 * @module @arcis/node/sanitizers/command
 * Command injection prevention
 */

import { COMMAND_PATTERNS, BLOCKED } from '../core/constants';
import type { SanitizeResult, ThreatInfo } from '../core/types';

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
export function sanitizeCommand(input: string, collectThreats?: false): string;
export function sanitizeCommand(input: string, collectThreats: true): SanitizeResult;
export function sanitizeCommand(input: string, collectThreats = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats 
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let value = input;
  let wasSanitized = false;

  for (const pattern of COMMAND_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.lastIndex = 0;
    
    if (pattern.test(value)) {
      pattern.lastIndex = 0; // Reset again for replace
      
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: 'command_injection',
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
 * Checks if a string contains command injection patterns.
 * Does not sanitize — use sanitizeCommand() for that.
 * 
 * @param input - The string to check
 * @returns True if command injection patterns detected
 */
export function detectCommandInjection(input: string): boolean {
  if (typeof input !== 'string') return false;
  
  for (const pattern of COMMAND_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }
  
  return false;
}
