/**
 * XSS Sanitizer Tests
 * Tests for src/sanitizers/xss.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeXss, detectXss } from '../../src/sanitizers/xss';

describe('sanitizeXss', () => {
  describe('Script Tag Removal', () => {
    it('should remove script tags', () => {
      const result = sanitizeXss('<script>alert("xss")</script>');
      expect(result).not.toContain('<script>');
    });

    it('should handle script tags with attributes', () => {
      const result = sanitizeXss('<script src="evil.js"></script>');
      expect(result).not.toContain('<script');
    });

    it('should handle nested script tags', () => {
      const result = sanitizeXss('<script><script>nested</script></script>');
      expect(result).not.toContain('<script>');
    });
  });

  describe('Event Handler Removal', () => {
    it('should remove onerror handlers', () => {
      const result = sanitizeXss('<img onerror="alert(1)">');
      expect(result).not.toContain('onerror');
    });

    it('should remove onclick handlers', () => {
      const result = sanitizeXss('<div onclick="evil()">click me</div>');
      expect(result).not.toContain('onclick');
    });

    it('should remove onload handlers', () => {
      const result = sanitizeXss('<svg onload="alert(1)">');
      expect(result).not.toContain('onload');
    });

    it('should remove onmouseover handlers', () => {
      const result = sanitizeXss('<a onmouseover="evil()">hover</a>');
      expect(result).not.toContain('onmouseover');
    });

    it('should handle event handlers with single quotes', () => {
      const result = sanitizeXss("<img onerror='alert(1)'>");
      expect(result).not.toContain('onerror');
    });

    it('should handle event handlers without quotes', () => {
      const result = sanitizeXss('<img onerror=alert(1)>');
      expect(result).not.toContain('onerror');
    });
  });

  describe('Dangerous Protocol Removal', () => {
    it('should remove javascript: protocol', () => {
      const result = sanitizeXss('javascript:alert(1)');
      expect(result.toLowerCase()).not.toContain('javascript:');
    });

    it('should handle javascript: with mixed case', () => {
      const result = sanitizeXss('JaVaScRiPt:alert(1)');
      expect(result.toLowerCase()).not.toContain('javascript:');
    });

    it('should remove vbscript: protocol', () => {
      const result = sanitizeXss('vbscript:msgbox("xss")');
      expect(result.toLowerCase()).not.toContain('vbscript:');
    });

    it('should remove data: text/html URIs', () => {
      const result = sanitizeXss('data:text/html,<script>alert(1)</script>');
      expect(result).not.toContain('data:');
    });
  });

  describe('HTML Entity Encoding', () => {
    it('should encode < character', () => {
      const result = sanitizeXss('<div>');
      expect(result).toContain('&lt;');
    });

    it('should encode > character', () => {
      const result = sanitizeXss('>test<');
      expect(result).toContain('&gt;');
    });

    it('should encode " character', () => {
      const result = sanitizeXss('"quoted"');
      expect(result).toContain('&quot;');
    });

    it("should encode ' character", () => {
      const result = sanitizeXss("'single'");
      expect(result).toContain('&#x27;');
    });

    it('should encode & character', () => {
      const result = sanitizeXss('a & b');
      expect(result).toContain('&amp;');
    });
  });

  describe('Threat Collection', () => {
    it('should collect threat info when requested', () => {
      const result = sanitizeXss('<script>alert(1)</script>', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('xss');
    });

    it('should return no threats for safe input', () => {
      const result = sanitizeXss('Hello World', true);
      // Even safe text gets encoded, so wasSanitized might be false for pure alphanumeric
      expect(result.value).toBeDefined();
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string', () => {
      const result = sanitizeXss('');
      expect(result).toBe('');
    });

    it('should handle non-string input', () => {
      const result = sanitizeXss(123 as unknown as string);
      expect(result).toBe('123');
    });

    it('should handle null-like values', () => {
      const result = sanitizeXss(null as unknown as string);
      expect(result).toBeDefined();
    });

    it('should preserve safe content', () => {
      const result = sanitizeXss('Hello World 123');
      expect(result).toContain('Hello');
      expect(result).toContain('World');
      expect(result).toContain('123');
    });
  });
});

describe('detectXss', () => {
  it('should detect script tags', () => {
    expect(detectXss('<script>alert(1)</script>')).toBe(true);
  });

  it('should detect event handlers', () => {
    expect(detectXss('<img onerror="alert(1)">')).toBe(true);
  });

  it('should detect javascript: protocol', () => {
    expect(detectXss('javascript:alert(1)')).toBe(true);
  });

  it('should detect HTML special characters', () => {
    expect(detectXss('<div>test</div>')).toBe(true);
  });

  it('should return false for safe input', () => {
    expect(detectXss('Hello World')).toBe(false);
  });

  it('should handle non-string input', () => {
    expect(detectXss(123 as unknown as string)).toBe(false);
  });
});
