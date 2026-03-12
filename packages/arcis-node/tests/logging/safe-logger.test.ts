/**
 * Safe Logger / Redactor Tests
 * Tests for src/logging/redactor.ts
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSafeLogger, createRedactor, safeLog } from '../../src/logging/redactor';
import { REDACTION } from '../../src/core/constants';

describe('createSafeLogger', () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  describe('Basic Logging', () => {
    it('should log info messages', () => {
      const logger = createSafeLogger();
      logger.info('Test message');

      expect(consoleLogSpy).toHaveBeenCalled();
      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.level).toBe('info');
      expect(output.message).toBe('Test message');
      expect(output.timestamp).toBeDefined();
    });

    it('should log warn messages', () => {
      const logger = createSafeLogger();
      logger.warn('Warning message');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.level).toBe('warn');
    });

    it('should log error messages', () => {
      const logger = createSafeLogger();
      logger.error('Error message');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.level).toBe('error');
    });

    it('should log debug messages', () => {
      const logger = createSafeLogger();
      logger.debug('Debug message');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.level).toBe('debug');
    });

    it('should log with custom level', () => {
      const logger = createSafeLogger();
      logger.log('custom', 'Custom level message');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.level).toBe('custom');
    });

    it('should include data when provided', () => {
      const logger = createSafeLogger();
      logger.info('User action', { userId: 123, action: 'login' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data).toEqual({ userId: 123, action: 'login' });
    });
  });

  describe('Sensitive Data Redaction', () => {
    it('should redact password fields', () => {
      const logger = createSafeLogger();
      logger.info('User login', { email: 'user@test.com', password: 'secret123' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.email).toBe('user@test.com');
      expect(output.data.password).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact token fields', () => {
      const logger = createSafeLogger();
      logger.info('Auth', { token: 'abc123', apiKey: 'key123' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.token).toBe(REDACTION.REPLACEMENT);
      expect(output.data.apiKey).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact authorization fields', () => {
      const logger = createSafeLogger();
      logger.info('Request', { authorization: 'Bearer xyz', auth: 'secret' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.authorization).toBe(REDACTION.REPLACEMENT);
      expect(output.data.auth).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact credit card fields', () => {
      const logger = createSafeLogger();
      logger.info('Payment', { creditcard: '4111111111111111', cc: '5500' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.creditcard).toBe(REDACTION.REPLACEMENT);
      expect(output.data.cc).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact SSN fields', () => {
      const logger = createSafeLogger();
      logger.info('User data', { ssn: '123-45-6789', social_security: '987654321' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.ssn).toBe(REDACTION.REPLACEMENT);
      expect(output.data.social_security).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact session/cookie fields', () => {
      const logger = createSafeLogger();
      logger.info('Session', { session: 'sess_123', cookie: 'cookie_value' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.session).toBe(REDACTION.REPLACEMENT);
      expect(output.data.cookie).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact JWT fields', () => {
      const logger = createSafeLogger();
      logger.info('Token', { jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', bearer: 'token' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.jwt).toBe(REDACTION.REPLACEMENT);
      expect(output.data.bearer).toBe(REDACTION.REPLACEMENT);
    });

    it('should be case-insensitive for redaction', () => {
      const logger = createSafeLogger();
      logger.info('Mixed case', { 
        PASSWORD: 'secret1',
        PassWord: 'secret2',
        Token: 'abc',
      });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.PASSWORD).toBe(REDACTION.REPLACEMENT);
      expect(output.data.PassWord).toBe(REDACTION.REPLACEMENT);
      expect(output.data.Token).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact nested sensitive fields', () => {
      const logger = createSafeLogger();
      logger.info('Nested', {
        user: {
          email: 'test@test.com',
          credentials: {
            password: 'secret',
          },
        },
      });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.user.email).toBe('test@test.com');
      expect(output.data.user.credentials).toBe(REDACTION.REPLACEMENT);
    });

    it('should redact arrays with sensitive data', () => {
      const logger = createSafeLogger();
      logger.info('Array', {
        users: [
          { name: 'John', password: 'pass1' },
          { name: 'Jane', password: 'pass2' },
        ],
      });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.users[0].name).toBe('John');
      expect(output.data.users[0].password).toBe(REDACTION.REPLACEMENT);
      expect(output.data.users[1].password).toBe(REDACTION.REPLACEMENT);
    });
  });

  describe('Custom Redact Keys', () => {
    it('should redact custom keys', () => {
      const logger = createSafeLogger({
        redactKeys: ['customToken', 'internalId'],
      });
      logger.info('Custom', { customToken: 'abc', internalId: '123', name: 'test' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.customToken).toBe(REDACTION.REPLACEMENT);
      expect(output.data.internalId).toBe(REDACTION.REPLACEMENT);
      expect(output.data.name).toBe('test');
    });

    it('should still redact default keys with custom keys', () => {
      const logger = createSafeLogger({
        redactKeys: ['mySecret'],
      });
      logger.info('Both', { mySecret: 'x', password: 'y' });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.mySecret).toBe(REDACTION.REPLACEMENT);
      expect(output.data.password).toBe(REDACTION.REPLACEMENT);
    });
  });

  describe('Log Injection Prevention', () => {
    it('should remove newlines from messages', () => {
      const logger = createSafeLogger();
      logger.info('Line1\nLine2\rLine3');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.message).not.toContain('\n');
      expect(output.message).not.toContain('\r');
    });

    it('should remove tabs from messages', () => {
      const logger = createSafeLogger();
      logger.info('Before\tAfter');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.message).not.toContain('\t');
    });

    it('should remove control characters from messages', () => {
      const logger = createSafeLogger();
      logger.info('Test\x00\x1F message');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.message).not.toContain('\x00');
      expect(output.message).not.toContain('\x1F');
    });
  });

  describe('Message Truncation', () => {
    it('should truncate long messages', () => {
      const logger = createSafeLogger({ maxLength: 50 });
      const longMessage = 'A'.repeat(100);
      logger.info(longMessage);

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.message.length).toBeLessThan(100);
      expect(output.message).toContain(REDACTION.TRUNCATED);
    });

    it('should not truncate short messages', () => {
      const logger = createSafeLogger({ maxLength: 100 });
      logger.info('Short message');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.message).toBe('Short message');
      expect(output.message).not.toContain(REDACTION.TRUNCATED);
    });
  });

  describe('Custom Redaction Patterns', () => {
    it('should apply custom redaction patterns to messages', () => {
      const logger = createSafeLogger({
        redactPatterns: [/api_key_[a-z0-9]+/gi],
      });
      logger.info('Using api_key_abc123 for request');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.message).toContain(REDACTION.REPLACEMENT);
      expect(output.message).not.toContain('api_key_abc123');
    });

    it('should apply multiple custom patterns', () => {
      const logger = createSafeLogger({
        redactPatterns: [/token_[a-z0-9]+/gi, /secret_[0-9]+/gi],
      });
      logger.info('token_xyz and secret_123');

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.message).not.toContain('token_xyz');
      expect(output.message).not.toContain('secret_123');
    });
  });

  describe('Max Depth Protection', () => {
    it('should handle deeply nested objects', () => {
      const logger = createSafeLogger();
      
      // Create deeply nested object (more than MAX_RECURSION_DEPTH)
      let nested: Record<string, unknown> = { value: 'bottom' };
      for (let i = 0; i < 15; i++) {
        nested = { nested };
      }
      
      logger.info('Deep nesting', nested);

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(JSON.stringify(output)).toContain(REDACTION.MAX_DEPTH);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null values', () => {
      const logger = createSafeLogger();
      logger.info('Null data', { value: null });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data.value).toBeNull();
    });

    it('should handle undefined values', () => {
      const logger = createSafeLogger();
      logger.info('Undefined data', { value: undefined });

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      // undefined is not serializable in JSON, so it will be omitted
      expect('value' in output.data).toBe(false);
    });

    it('should handle primitives', () => {
      const logger = createSafeLogger();
      logger.info('Primitive', 123);

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data).toBe(123);
    });

    it('should handle empty objects', () => {
      const logger = createSafeLogger();
      logger.info('Empty', {});

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data).toEqual({});
    });

    it('should handle empty arrays', () => {
      const logger = createSafeLogger();
      logger.info('Empty array', []);

      const output = JSON.parse(consoleLogSpy.mock.calls[0][0]);
      expect(output.data).toEqual([]);
    });
  });
});

describe('createRedactor', () => {
  it('should create a redactor function', () => {
    const redact = createRedactor();
    expect(typeof redact).toBe('function');
  });

  it('should redact default sensitive keys', () => {
    const redact = createRedactor();
    const result = redact({ password: 'secret', name: 'test' });

    expect(result).toEqual({
      password: REDACTION.REPLACEMENT,
      name: 'test',
    });
  });

  it('should redact custom keys', () => {
    const redact = createRedactor(['mySecret']);
    const result = redact({ mySecret: 'abc', value: 123 });

    expect(result).toEqual({
      mySecret: REDACTION.REPLACEMENT,
      value: 123,
    });
  });

  it('should redact nested sensitive keys', () => {
    const redact = createRedactor();
    const result = redact({
      user: {
        name: 'John',
        credentials: {
          password: 'secret',
        },
      },
    });

    expect(result).toEqual({
      user: {
        name: 'John',
        credentials: REDACTION.REPLACEMENT,
      },
    });
  });

  it('should handle arrays', () => {
    const redact = createRedactor();
    const result = redact([{ password: 'a' }, { password: 'b' }]);

    expect(result).toEqual([
      { password: REDACTION.REPLACEMENT },
      { password: REDACTION.REPLACEMENT },
    ]);
  });

  it('should handle null and undefined', () => {
    const redact = createRedactor();
    expect(redact(null)).toBeNull();
    expect(redact(undefined)).toBeUndefined();
  });

  it('should return primitives unchanged', () => {
    const redact = createRedactor();
    expect(redact(123)).toBe(123);
    expect(redact('string')).toBe('string');
    expect(redact(true)).toBe(true);
  });

  it('should handle max depth', () => {
    const redact = createRedactor();
    
    // Create deeply nested object
    let nested: Record<string, unknown> = { value: 'bottom' };
    for (let i = 0; i < 15; i++) {
      nested = { nested };
    }
    
    const result = redact(nested);
    expect(JSON.stringify(result)).toContain(REDACTION.MAX_DEPTH);
  });
});

describe('safeLog', () => {
  it('should be an alias for createSafeLogger', () => {
    expect(safeLog).toBe(createSafeLogger);
  });
});
