/**
 * @module @arcis/node/sanitizers/xss
 * XSS (Cross-Site Scripting) prevention
 */

import { XSS_PATTERNS } from '../core/constants';
import { encodeHtmlEntities } from './utils';
import type { SanitizeResult, ThreatInfo } from '../core/types';

/**
 * Sanitizes a string to prevent XSS attacks.
 * 
 * Strategy:
 * 1. Remove dangerous patterns (script tags, event handlers, etc.)
 * 2. HTML-encode the remaining content
 * 
 * @param input - The string to sanitize
 * @param collectThreats - Whether to collect threat information (default: false for performance)
 * @returns Sanitized string or SanitizeResult if collectThreats is true
 * 
 * @example
 * sanitizeXss("<script>alert('xss')</script>")
 * // Returns: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
 * 
 * @example
 * sanitizeXss("<img onerror='alert(1)'>")
 * // Returns: "&lt;img&gt;" (event handler removed)
 */
export function sanitizeXss(input: string, collectThreats?: false): string;
export function sanitizeXss(input: string, collectThreats: true): SanitizeResult;
export function sanitizeXss(input: string, collectThreats = false): string | SanitizeResult {
  if (typeof input !== 'string') {
    return collectThreats 
      ? { value: String(input), wasSanitized: false, threats: [] }
      : String(input);
  }

  const threats: ThreatInfo[] = [];
  let value = input;
  let wasSanitized = false;

  // Patterns to REMOVE (not just encode) - these are dangerous even when encoded
  const removePatterns = [
    // Event handlers: onclick="...", onerror='...', etc.
    /\s+on\w+\s*=\s*["'][^"']*["']/gi,
    /\s+on\w+\s*=\s*[^\s>]*/gi,
    // javascript: protocol
    /javascript\s*:/gi,
    // vbscript: protocol  
    /vbscript\s*:/gi,
    // data: URIs with HTML/script content
    /data\s*:\s*text\/html[^>\s]*/gi,
  ];

  // Remove dangerous patterns FIRST
  for (const pattern of removePatterns) {
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      
      if (collectThreats) {
        const matches = value.match(pattern);
        if (matches) {
          for (const match of matches) {
            threats.push({
              type: 'xss',
              pattern: pattern.source,
              original: match,
            });
          }
        }
      }
      
      value = value.replace(pattern, '');
      wasSanitized = true;
    }
  }

  // Also check for patterns from XSS_PATTERNS for threat collection
  if (collectThreats) {
    for (const pattern of XSS_PATTERNS) {
      pattern.lastIndex = 0;
      const matches = value.match(pattern);
      if (matches) {
        for (const match of matches) {
          // Avoid duplicates
          if (!threats.some(t => t.original === match)) {
            threats.push({
              type: 'xss',
              pattern: pattern.source,
              original: match,
            });
          }
        }
      }
    }
  }

  // THEN HTML-encode ALL special characters - this is the primary defense
  // This converts < to &lt; which is safe for display
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

/**
 * Checks if a string contains potential XSS patterns.
 * Does not sanitize — use sanitizeXss() for that.
 * 
 * @param input - The string to check
 * @returns True if XSS patterns detected
 */
export function detectXss(input: string): boolean {
  if (typeof input !== 'string') return false;
  
  // Check for event handlers
  if (/\s+on\w+\s*=/i.test(input)) return true;
  
  // Check for dangerous protocols
  if (/javascript\s*:/i.test(input)) return true;
  if (/vbscript\s*:/i.test(input)) return true;
  if (/data\s*:\s*text\/html/i.test(input)) return true;
  
  // Check for patterns from constants
  for (const pattern of XSS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      return true;
    }
  }
  
  // Also check for characters that would be encoded
  return /[<>"'&]/.test(input);
}
