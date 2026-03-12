/**
 * @module @arcis/node/validation/file
 * File upload validation and filename sanitization
 */

// =============================================================================
// MAGIC BYTES — first bytes of common file types
// =============================================================================

const MAGIC_BYTES: Record<string, Buffer[]> = {
  // Images
  'image/jpeg': [Buffer.from([0xFF, 0xD8, 0xFF])],
  'image/png': [Buffer.from([0x89, 0x50, 0x4E, 0x47])],
  'image/gif': [Buffer.from('GIF87a'), Buffer.from('GIF89a')],
  'image/webp': [Buffer.from('RIFF')], // RIFF....WEBP
  'image/bmp': [Buffer.from([0x42, 0x4D])],
  'image/svg+xml': [], // text-based, check separately

  // Documents
  'application/pdf': [Buffer.from('%PDF')],
  'application/zip': [Buffer.from([0x50, 0x4B, 0x03, 0x04])],

  // Audio/Video
  'audio/mpeg': [Buffer.from([0xFF, 0xFB]), Buffer.from([0xFF, 0xF3]), Buffer.from([0x49, 0x44, 0x33])],
  'video/mp4': [], // ftyp at offset 4
};

// =============================================================================
// DANGEROUS EXTENSIONS — files that can execute code
// =============================================================================

const DANGEROUS_EXTENSIONS = new Set([
  // Scripts
  '.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
  '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh',
  '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2',
  '.sh', '.bash', '.csh', '.ksh',
  // Server-side
  '.php', '.php3', '.php4', '.php5', '.phtml', '.pht',
  '.asp', '.aspx', '.ashx', '.asmx', '.cer',
  '.jsp', '.jspx', '.jsw', '.jsv',
  '.cgi', '.pl', '.py', '.rb',
  // Java
  '.jar', '.war', '.ear', '.class',
  // Config that can execute
  '.htaccess', '.htpasswd',
  // Template engines
  '.ejs', '.pug', '.hbs', '.handlebars', '.njk', '.twig',
  // Shortcuts/links
  '.lnk', '.inf', '.reg', '.url',
  // Office macros
  '.docm', '.xlsm', '.pptm', '.dotm',
]);

// =============================================================================
// TYPES
// =============================================================================

/** File upload validation options */
export interface ValidateFileOptions {
  /** Maximum file size in bytes. Default: 5MB */
  maxSize?: number;
  /** Allowed MIME types (e.g., ['image/jpeg', 'image/png']) */
  allowedTypes?: string[];
  /** Allowed file extensions (e.g., ['.jpg', '.png']). Includes dot. */
  allowedExtensions?: string[];
  /** Block dangerous/executable extensions. Default: true */
  blockExecutables?: boolean;
  /** Validate magic bytes match the claimed MIME type. Default: true */
  validateMagicBytes?: boolean;
  /** Block files with no extension. Default: true */
  blockNoExtension?: boolean;
  /** Block double extensions (e.g., file.php.jpg). Default: true */
  blockDoubleExtensions?: boolean;
}

/** File metadata for validation */
export interface FileInput {
  /** Original filename */
  filename: string;
  /** MIME type (as claimed by client) */
  mimetype: string;
  /** File size in bytes */
  size: number;
  /** File content buffer (for magic byte validation) */
  buffer?: Buffer;
}

/** File validation result */
export interface ValidateFileResult {
  /** Whether the file passed validation */
  valid: boolean;
  /** Validation errors (empty if valid) */
  errors: string[];
  /** Sanitized filename (safe for storage) */
  sanitizedFilename: string;
}

// =============================================================================
// DEFAULTS
// =============================================================================

const DEFAULT_MAX_SIZE = 5 * 1024 * 1024; // 5MB

// =============================================================================
// FILENAME SANITIZATION
// =============================================================================

/**
 * Sanitize a filename for safe storage.
 *
 * Strips path traversal, null bytes, control characters, and special characters.
 * Preserves the extension and converts to a filesystem-safe name.
 *
 * @param filename - The original filename
 * @returns A sanitized filename safe for storage
 *
 * @example
 * sanitizeFilename('../../etc/passwd')          // 'etc_passwd'
 * sanitizeFilename('file<name>.jpg')            // 'filename.jpg'
 * sanitizeFilename('photo (1).jpg')             // 'photo_1.jpg'
 * sanitizeFilename('.htaccess')                 // 'htaccess'
 */
export function sanitizeFilename(filename: string): string {
  let name = filename;

  // Strip null bytes
  name = name.replace(/\0/g, '');

  // Strip path components (both Unix and Windows)
  name = name.replace(/^.*[/\\]/, '');

  // Strip control characters
  name = name.replace(/[\x00-\x1F\x7F]/g, '');

  // Strip characters unsafe for filesystems
  name = name.replace(/[<>:"/\\|?*]/g, '');

  // Replace spaces and parens with underscores
  name = name.replace(/[\s()]+/g, '_');

  // Strip leading dots (hidden files / .htaccess)
  name = name.replace(/^\.+/, '');

  // Collapse multiple underscores/dots
  name = name.replace(/_{2,}/g, '_');
  name = name.replace(/\.{2,}/g, '.');

  // Trim underscores before dots (e.g., "photo_1_.jpg" → "photo_1.jpg")
  name = name.replace(/_+\./g, '.');

  // Trim underscores from edges
  name = name.replace(/^_+|_+$/g, '');

  // Fallback for empty name
  if (!name || name === '.') {
    name = 'unnamed';
  }

  return name;
}

// =============================================================================
// MAGIC BYTE VALIDATION
// =============================================================================

/**
 * Check if file content matches the claimed MIME type via magic bytes.
 */
function matchesMagicBytes(buffer: Buffer, mimetype: string): boolean {
  const signatures = MAGIC_BYTES[mimetype];
  if (!signatures || signatures.length === 0) return true; // no signature to check

  return signatures.some(sig => {
    if (buffer.length < sig.length) return false;
    return buffer.subarray(0, sig.length).equals(sig);
  });
}

// =============================================================================
// EXTENSION HELPERS
// =============================================================================

/**
 * Get the extension from a filename (lowercase, with dot).
 */
function getExtension(filename: string): string {
  const lastDot = filename.lastIndexOf('.');
  if (lastDot < 1) return '';
  return filename.slice(lastDot).toLowerCase();
}

/**
 * Check if a filename has double extensions (e.g., file.php.jpg).
 */
function hasDoubleExtension(filename: string): boolean {
  const parts = filename.split('.');
  if (parts.length < 3) return false;

  // Check if any non-final extension is dangerous
  for (let i = 1; i < parts.length - 1; i++) {
    const ext = '.' + parts[i].toLowerCase();
    if (DANGEROUS_EXTENSIONS.has(ext)) return true;
  }
  return false;
}

// =============================================================================
// FILE VALIDATION
// =============================================================================

/**
 * Validate a file upload for security.
 *
 * Checks file size, MIME type, extension, magic bytes, and dangerous patterns.
 * Returns a result with validation errors and a sanitized filename.
 *
 * @param file - File metadata and optional content
 * @param options - Validation options
 * @returns Validation result
 *
 * @example
 * const result = validateFile(
 *   { filename: 'photo.jpg', mimetype: 'image/jpeg', size: 1024, buffer },
 *   { allowedTypes: ['image/jpeg', 'image/png'], maxSize: 2 * 1024 * 1024 }
 * );
 * if (!result.valid) {
 *   return res.status(400).json({ errors: result.errors });
 * }
 * // Use result.sanitizedFilename for storage
 *
 * @example
 * // Block executables only (no whitelist)
 * const result = validateFile(file, { blockExecutables: true });
 */
export function validateFile(
  file: FileInput,
  options: ValidateFileOptions = {}
): ValidateFileResult {
  const {
    maxSize = DEFAULT_MAX_SIZE,
    allowedTypes,
    allowedExtensions,
    blockExecutables = true,
    validateMagicBytes = true,
    blockNoExtension = true,
    blockDoubleExtensions = true,
  } = options;

  const errors: string[] = [];
  const sanitizedFilename = sanitizeFilename(file.filename);
  const extension = getExtension(sanitizedFilename);

  // Size check
  if (file.size > maxSize) {
    errors.push(`File size ${file.size} exceeds maximum ${maxSize} bytes`);
  }

  if (file.size === 0) {
    errors.push('File is empty');
  }

  // Extension checks
  if (blockNoExtension && !extension) {
    errors.push('File has no extension');
  }

  if (blockExecutables && extension && DANGEROUS_EXTENSIONS.has(extension)) {
    errors.push(`Executable extension "${extension}" is not allowed`);
  }

  if (blockDoubleExtensions && hasDoubleExtension(sanitizedFilename)) {
    errors.push('Double extensions with executable types are not allowed');
  }

  if (allowedExtensions && extension) {
    const normalizedAllowed = allowedExtensions.map(e => e.toLowerCase());
    if (!normalizedAllowed.includes(extension)) {
      errors.push(`Extension "${extension}" is not allowed. Allowed: ${normalizedAllowed.join(', ')}`);
    }
  }

  // MIME type check
  if (allowedTypes && !allowedTypes.includes(file.mimetype)) {
    errors.push(`MIME type "${file.mimetype}" is not allowed. Allowed: ${allowedTypes.join(', ')}`);
  }

  // Magic bytes validation
  if (validateMagicBytes && file.buffer && file.buffer.length > 0) {
    if (!matchesMagicBytes(file.buffer, file.mimetype)) {
      errors.push(`File content does not match claimed MIME type "${file.mimetype}"`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    sanitizedFilename,
  };
}

/**
 * Check if a file extension is considered dangerous/executable.
 *
 * @param filename - Filename or extension to check
 * @returns true if the extension is dangerous
 */
export function isDangerousExtension(filename: string): boolean {
  const ext = getExtension(filename);
  return ext !== '' && DANGEROUS_EXTENSIONS.has(ext);
}
