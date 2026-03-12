/**
 * File Upload Validation Tests
 * Tests for src/validation/file.ts
 */

import { describe, it, expect } from 'vitest';
import { sanitizeFilename, validateFile, isDangerousExtension } from '../../src/validation/file';
import type { FileInput } from '../../src/validation/file';

describe('sanitizeFilename', () => {
  it('should strip path traversal', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('passwd');
    expect(sanitizeFilename('..\\..\\windows\\system32')).toBe('system32');
  });

  it('should strip null bytes', () => {
    expect(sanitizeFilename('file\0name.jpg')).toBe('filename.jpg');
  });

  it('should strip control characters', () => {
    expect(sanitizeFilename('file\x01\x02name.jpg')).toBe('filename.jpg');
  });

  it('should strip unsafe filesystem characters', () => {
    expect(sanitizeFilename('file<name>.jpg')).toBe('filename.jpg');
    expect(sanitizeFilename('file:name.jpg')).toBe('filename.jpg');
    expect(sanitizeFilename('file"name".jpg')).toBe('filename.jpg');
    expect(sanitizeFilename('file|name.jpg')).toBe('filename.jpg');
    expect(sanitizeFilename('file?name.jpg')).toBe('filename.jpg');
    expect(sanitizeFilename('file*name.jpg')).toBe('filename.jpg');
  });

  it('should replace spaces and parens with underscores', () => {
    expect(sanitizeFilename('photo (1).jpg')).toBe('photo_1.jpg');
    expect(sanitizeFilename('my file name.jpg')).toBe('my_file_name.jpg');
  });

  it('should strip leading dots', () => {
    expect(sanitizeFilename('.htaccess')).toBe('htaccess');
    expect(sanitizeFilename('..hidden')).toBe('hidden');
    expect(sanitizeFilename('.env')).toBe('env');
  });

  it('should collapse multiple underscores and dots', () => {
    expect(sanitizeFilename('file___name.jpg')).toBe('file_name.jpg');
    expect(sanitizeFilename('file...jpg')).toBe('file.jpg');
  });

  it('should return unnamed for empty input', () => {
    expect(sanitizeFilename('')).toBe('unnamed');
    expect(sanitizeFilename('...')).toBe('unnamed');
    expect(sanitizeFilename('\0')).toBe('unnamed');
  });

  it('should preserve valid filenames', () => {
    expect(sanitizeFilename('photo.jpg')).toBe('photo.jpg');
    expect(sanitizeFilename('document-v2.pdf')).toBe('document-v2.pdf');
    expect(sanitizeFilename('report_2024.xlsx')).toBe('report_2024.xlsx');
  });

  it('should handle Windows paths', () => {
    expect(sanitizeFilename('C:\\Users\\admin\\photo.jpg')).toBe('photo.jpg');
  });

  it('should handle Unix paths', () => {
    expect(sanitizeFilename('/home/user/photo.jpg')).toBe('photo.jpg');
  });
});

describe('isDangerousExtension', () => {
  it('should flag executable extensions', () => {
    expect(isDangerousExtension('file.exe')).toBe(true);
    expect(isDangerousExtension('file.bat')).toBe(true);
    expect(isDangerousExtension('file.sh')).toBe(true);
    expect(isDangerousExtension('file.php')).toBe(true);
    expect(isDangerousExtension('file.jsp')).toBe(true);
    expect(isDangerousExtension('file.ps1')).toBe(true);
  });

  it('should flag server-side extensions', () => {
    expect(isDangerousExtension('file.asp')).toBe(true);
    expect(isDangerousExtension('file.aspx')).toBe(true);
    expect(isDangerousExtension('file.phtml')).toBe(true);
    expect(isDangerousExtension('file.cgi')).toBe(true);
  });

  it('should flag template engine extensions', () => {
    expect(isDangerousExtension('file.ejs')).toBe(true);
    expect(isDangerousExtension('file.pug')).toBe(true);
    expect(isDangerousExtension('file.hbs')).toBe(true);
  });

  it('should flag office macro extensions', () => {
    expect(isDangerousExtension('file.docm')).toBe(true);
    expect(isDangerousExtension('file.xlsm')).toBe(true);
  });

  it('should allow safe extensions', () => {
    expect(isDangerousExtension('file.jpg')).toBe(false);
    expect(isDangerousExtension('file.png')).toBe(false);
    expect(isDangerousExtension('file.pdf')).toBe(false);
    expect(isDangerousExtension('file.txt')).toBe(false);
    expect(isDangerousExtension('file.docx')).toBe(false);
    expect(isDangerousExtension('file.csv')).toBe(false);
  });

  it('should be case insensitive', () => {
    expect(isDangerousExtension('file.EXE')).toBe(true);
    expect(isDangerousExtension('file.Php')).toBe(true);
  });
});

describe('validateFile', () => {
  const makeFile = (overrides: Partial<FileInput> = {}): FileInput => ({
    filename: 'photo.jpg',
    mimetype: 'image/jpeg',
    size: 1024,
    buffer: Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]),
    ...overrides,
  });

  describe('Size Validation', () => {
    it('should accept files within size limit', () => {
      const result = validateFile(makeFile({ size: 1024 }), { maxSize: 2048 });
      expect(result.valid).toBe(true);
    });

    it('should reject files exceeding size limit', () => {
      const result = validateFile(makeFile({ size: 10_000_000 }), { maxSize: 5_000_000 });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('exceeds maximum');
    });

    it('should reject empty files', () => {
      const result = validateFile(makeFile({ size: 0 }));
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('File is empty');
    });
  });

  describe('Extension Validation', () => {
    it('should block executable extensions', () => {
      const result = validateFile(makeFile({ filename: 'shell.php' }));
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('.php');
    });

    it('should allow safe extensions', () => {
      const result = validateFile(makeFile({ filename: 'photo.jpg' }));
      expect(result.valid).toBe(true);
    });

    it('should enforce allowed extensions whitelist', () => {
      const result = validateFile(makeFile({ filename: 'doc.pdf' }), {
        allowedExtensions: ['.jpg', '.png'],
      });
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('.pdf');
    });

    it('should block files with no extension', () => {
      const result = validateFile(makeFile({ filename: 'noext' }));
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('File has no extension');
    });

    it('should allow files with no extension when configured', () => {
      const result = validateFile(makeFile({ filename: 'noext' }), { blockNoExtension: false });
      expect(result.valid).toBe(true);
    });
  });

  describe('Double Extension Blocking', () => {
    it('should block dangerous double extensions', () => {
      const result = validateFile(makeFile({ filename: 'shell.php.jpg' }));
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Double extensions');
    });

    it('should allow safe double extensions', () => {
      const result = validateFile(makeFile({ filename: 'archive.tar.gz' }));
      expect(result.valid).toBe(true);
    });
  });

  describe('MIME Type Validation', () => {
    it('should enforce allowed MIME types', () => {
      const result = validateFile(
        makeFile({ mimetype: 'application/pdf' }),
        { allowedTypes: ['image/jpeg', 'image/png'] }
      );
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('application/pdf');
    });

    it('should accept allowed MIME types', () => {
      const result = validateFile(
        makeFile({ mimetype: 'image/jpeg' }),
        { allowedTypes: ['image/jpeg', 'image/png'] }
      );
      expect(result.valid).toBe(true);
    });
  });

  describe('Magic Bytes Validation', () => {
    it('should accept matching magic bytes', () => {
      const result = validateFile(makeFile({
        mimetype: 'image/jpeg',
        buffer: Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]),
      }));
      expect(result.valid).toBe(true);
    });

    it('should reject mismatched magic bytes', () => {
      const result = validateFile(makeFile({
        mimetype: 'image/jpeg',
        buffer: Buffer.from([0x89, 0x50, 0x4E, 0x47]), // PNG magic bytes
      }));
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('does not match');
    });

    it('should accept PNG with correct magic bytes', () => {
      const result = validateFile(makeFile({
        filename: 'image.png',
        mimetype: 'image/png',
        buffer: Buffer.from([0x89, 0x50, 0x4E, 0x47]),
      }));
      expect(result.valid).toBe(true);
    });

    it('should accept GIF with correct magic bytes', () => {
      const result = validateFile(makeFile({
        filename: 'anim.gif',
        mimetype: 'image/gif',
        buffer: Buffer.from('GIF89a'),
      }));
      expect(result.valid).toBe(true);
    });

    it('should skip magic bytes when no buffer provided', () => {
      const result = validateFile(makeFile({ buffer: undefined }));
      expect(result.valid).toBe(true);
    });

    it('should skip magic bytes when disabled', () => {
      const result = validateFile(
        makeFile({ mimetype: 'image/jpeg', buffer: Buffer.from([0x00, 0x00]) }),
        { validateMagicBytes: false }
      );
      expect(result.valid).toBe(true);
    });
  });

  describe('Sanitized Filename', () => {
    it('should return sanitized filename in result', () => {
      const result = validateFile(makeFile({ filename: '../../evil.jpg' }));
      expect(result.sanitizedFilename).toBe('evil.jpg');
    });
  });
});
