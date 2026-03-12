/**
 * Secure Cookie Defaults Middleware Tests
 * Tests for src/middleware/cookies.ts
 */

import { describe, it, expect } from 'vitest';
import { enforceSecureCookie, secureCookieDefaults, createSecureCookies } from '../../src/middleware/cookies';

describe('enforceSecureCookie', () => {
  const defaults = { httpOnly: true, secure: true, sameSite: 'Lax' as const };

  describe('HttpOnly', () => {
    it('should add HttpOnly when missing', () => {
      const result = enforceSecureCookie('session=abc123', defaults);
      expect(result).toContain('; HttpOnly');
    });

    it('should not duplicate HttpOnly', () => {
      const result = enforceSecureCookie('session=abc123; HttpOnly', defaults);
      expect(result.match(/HttpOnly/gi)?.length).toBe(1);
    });

    it('should skip HttpOnly when disabled', () => {
      const result = enforceSecureCookie('session=abc123', { ...defaults, httpOnly: false });
      expect(result).not.toContain('HttpOnly');
    });
  });

  describe('Secure', () => {
    it('should add Secure when missing', () => {
      const result = enforceSecureCookie('session=abc123', defaults);
      expect(result).toContain('; Secure');
    });

    it('should not duplicate Secure', () => {
      const result = enforceSecureCookie('session=abc123; Secure', defaults);
      expect(result.match(/; Secure/gi)?.length).toBe(1);
    });

    it('should skip Secure when disabled', () => {
      const result = enforceSecureCookie('session=abc123', { ...defaults, secure: false });
      expect(result).not.toContain('; Secure');
    });
  });

  describe('SameSite', () => {
    it('should add SameSite=Lax by default', () => {
      const result = enforceSecureCookie('session=abc123', defaults);
      expect(result).toContain('; SameSite=Lax');
    });

    it('should support SameSite=Strict', () => {
      const result = enforceSecureCookie('session=abc123', { ...defaults, sameSite: 'Strict' });
      expect(result).toContain('; SameSite=Strict');
    });

    it('should support SameSite=None and force Secure', () => {
      const result = enforceSecureCookie('session=abc123', { ...defaults, secure: false, sameSite: 'None' });
      expect(result).toContain('; SameSite=None');
      expect(result).toContain('; Secure');
    });

    it('should not duplicate SameSite', () => {
      const result = enforceSecureCookie('session=abc123; SameSite=Strict', defaults);
      expect(result.match(/SameSite/gi)?.length).toBe(1);
    });

    it('should skip SameSite when false', () => {
      const result = enforceSecureCookie('session=abc123', { ...defaults, sameSite: false });
      expect(result).not.toContain('SameSite');
    });
  });

  describe('Path', () => {
    it('should add Path when specified', () => {
      const result = enforceSecureCookie('session=abc123', { ...defaults, path: '/' });
      expect(result).toContain('; Path=/');
    });

    it('should override existing Path', () => {
      const result = enforceSecureCookie('session=abc123; Path=/old', { ...defaults, path: '/new' });
      expect(result).toContain('; Path=/new');
      expect(result).not.toContain('/old');
    });

    it('should not add Path when not specified', () => {
      const result = enforceSecureCookie('session=abc123', defaults);
      expect(result).not.toContain('Path');
    });
  });

  describe('Combined', () => {
    it('should add all missing attributes', () => {
      const result = enforceSecureCookie('session=abc123', defaults);
      expect(result).toBe('session=abc123; HttpOnly; Secure; SameSite=Lax');
    });

    it('should not modify already-secure cookies', () => {
      const cookie = 'session=abc123; HttpOnly; Secure; SameSite=Lax';
      const result = enforceSecureCookie(cookie, defaults);
      expect(result).toBe(cookie);
    });
  });
});

describe('createSecureCookies', () => {
  it('should be an alias for secureCookieDefaults', () => {
    expect(createSecureCookies).toBe(secureCookieDefaults);
  });
});
