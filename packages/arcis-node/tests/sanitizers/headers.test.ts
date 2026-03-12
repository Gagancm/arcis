/**
 * HTTP Header Injection Sanitizer Tests
 * Tests for src/sanitizers/headers.ts
 */

import { describe, it, expect } from 'vitest';
import {
  sanitizeHeaderValue,
  sanitizeHeaders,
  detectHeaderInjection,
} from '../../src/sanitizers/headers';

describe('sanitizeHeaderValue', () => {
  describe('CRLF Injection', () => {
    it('should strip CRLF sequence', () => {
      const result = sanitizeHeaderValue('value\r\nX-Injected: evil');
      expect(result).not.toContain('\r');
      expect(result).not.toContain('\n');
      expect(result).toBe('valueX-Injected: evil');
    });

    it('should strip bare carriage return', () => {
      const result = sanitizeHeaderValue('value\rinjected');
      expect(result).not.toContain('\r');
      expect(result).toBe('valueinjected');
    });

    it('should strip bare newline', () => {
      const result = sanitizeHeaderValue('value\ninjected');
      expect(result).not.toContain('\n');
      expect(result).toBe('valueinjected');
    });

    it('should strip multiple CRLF sequences', () => {
      const result = sanitizeHeaderValue('a\r\nb\r\nc');
      expect(result).toBe('abc');
    });

    it('should strip mixed CR, LF, and CRLF', () => {
      const result = sanitizeHeaderValue('a\rb\nc\r\nd');
      expect(result).toBe('abcd');
    });
  });

  describe('Null Byte Injection', () => {
    it('should strip null bytes', () => {
      const result = sanitizeHeaderValue('value\0truncated');
      expect(result).not.toContain('\0');
      expect(result).toBe('valuetruncated');
    });

    it('should strip null bytes combined with CRLF', () => {
      const result = sanitizeHeaderValue('value\0\r\nevil');
      expect(result).toBe('valueevil');
    });
  });

  describe('Response Splitting Attacks', () => {
    it('should prevent HTTP response splitting', () => {
      // Classic response splitting: inject a full HTTP response
      const result = sanitizeHeaderValue(
        'valid\r\n\r\n<html><script>alert(1)</script></html>'
      );
      expect(result).not.toContain('\r');
      expect(result).not.toContain('\n');
      expect(result).toContain('<html>');
    });

    it('should prevent header injection via Set-Cookie', () => {
      const result = sanitizeHeaderValue(
        'en\r\nSet-Cookie: session=hijacked'
      );
      expect(result).not.toContain('\r\n');
      expect(result).toBe('enSet-Cookie: session=hijacked');
    });

    it('should prevent Location header injection', () => {
      const result = sanitizeHeaderValue(
        'ok\r\nLocation: http://evil.com'
      );
      expect(result).toBe('okLocation: http://evil.com');
    });
  });

  describe('Safe Input', () => {
    it('should preserve normal header values', () => {
      expect(sanitizeHeaderValue('text/html; charset=utf-8')).toBe(
        'text/html; charset=utf-8'
      );
    });

    it('should preserve URLs in header values', () => {
      expect(sanitizeHeaderValue('https://example.com/path?q=1')).toBe(
        'https://example.com/path?q=1'
      );
    });

    it('should preserve bearer tokens', () => {
      expect(sanitizeHeaderValue('Bearer eyJhbGciOiJIUzI1NiJ9.test')).toBe(
        'Bearer eyJhbGciOiJIUzI1NiJ9.test'
      );
    });

    it('should preserve cache-control directives', () => {
      expect(sanitizeHeaderValue('no-cache, no-store, must-revalidate')).toBe(
        'no-cache, no-store, must-revalidate'
      );
    });

    it('should preserve empty string', () => {
      expect(sanitizeHeaderValue('')).toBe('');
    });
  });

  describe('Threat Collection', () => {
    it('should collect threat info when requested', () => {
      const result = sanitizeHeaderValue('value\r\ninjected', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('header_injection');
    });

    it('should collect multiple threats for multiple injections', () => {
      const result = sanitizeHeaderValue('a\r\nb\nc\rd', true);
      expect(result.threats.length).toBe(3);
    });

    it('should return no threats for safe input', () => {
      const result = sanitizeHeaderValue('application/json', true);
      expect(result.wasSanitized).toBe(false);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle non-string input', () => {
      const result = sanitizeHeaderValue(123 as unknown as string);
      expect(result).toBe('123');
    });

    it('should handle non-string input with collectThreats', () => {
      const result = sanitizeHeaderValue(null as unknown as string, true);
      expect(result.wasSanitized).toBe(false);
      expect(result.value).toBe('null');
    });

    it('should handle string with only CRLF', () => {
      const result = sanitizeHeaderValue('\r\n');
      expect(result).toBe('');
    });

    it('should handle consecutive null bytes', () => {
      const result = sanitizeHeaderValue('\0\0\0');
      expect(result).toBe('');
    });

    it('should handle unicode content safely', () => {
      const result = sanitizeHeaderValue('value-with-émojis-and-ñ');
      expect(result).toBe('value-with-émojis-and-ñ');
    });
  });
});

describe('sanitizeHeaders', () => {
  it('should sanitize both keys and values', () => {
    const result = sanitizeHeaders({
      'X-Custom\r\n': 'value\r\ninjected',
      'Content-Type': 'text/html',
    });
    expect(Object.keys(result)).not.toContain('X-Custom\r\n');
    expect(result['X-Custom']).toBe('valueinjected');
    expect(result['Content-Type']).toBe('text/html');
  });

  it('should return empty object for null input', () => {
    expect(sanitizeHeaders(null as unknown as Record<string, string>)).toEqual({});
  });

  it('should return empty object for non-object input', () => {
    expect(sanitizeHeaders('string' as unknown as Record<string, string>)).toEqual({});
  });

  it('should handle empty object', () => {
    expect(sanitizeHeaders({})).toEqual({});
  });

  it('should coerce non-string values to string', () => {
    const result = sanitizeHeaders({
      'X-Number': 42 as unknown as string,
    });
    expect(result['X-Number']).toBe('42');
  });

  it('should sanitize multiple headers', () => {
    const result = sanitizeHeaders({
      'X-A': 'a\r\nb',
      'X-B': 'c\nd',
      'X-C': 'safe',
    });
    expect(result['X-A']).toBe('ab');
    expect(result['X-B']).toBe('cd');
    expect(result['X-C']).toBe('safe');
  });
});

describe('detectHeaderInjection', () => {
  it('should detect CRLF', () => {
    expect(detectHeaderInjection('value\r\nevil')).toBe(true);
  });

  it('should detect bare CR', () => {
    expect(detectHeaderInjection('value\revil')).toBe(true);
  });

  it('should detect bare LF', () => {
    expect(detectHeaderInjection('value\nevil')).toBe(true);
  });

  it('should detect null byte', () => {
    expect(detectHeaderInjection('value\0evil')).toBe(true);
  });

  it('should return false for safe input', () => {
    expect(detectHeaderInjection('application/json')).toBe(false);
  });

  it('should return false for empty string', () => {
    expect(detectHeaderInjection('')).toBe(false);
  });

  it('should handle non-string input', () => {
    expect(detectHeaderInjection(123 as unknown as string)).toBe(false);
  });
});
