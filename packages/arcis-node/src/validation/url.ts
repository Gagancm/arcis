/**
 * @module @arcis/node/validation/url
 * SSRF (Server-Side Request Forgery) prevention
 *
 * Validates URLs to ensure they don't target private/internal networks,
 * localhost, cloud metadata endpoints, or use dangerous protocols.
 *
 * @example
 * import { validateUrl } from '@arcis/node';
 *
 * // Block SSRF attempts
 * validateUrl('http://169.254.169.254/latest/meta-data/')  // { safe: false, reason: 'link-local address' }
 * validateUrl('http://10.0.0.1/admin')                     // { safe: false, reason: 'private address (10.0.0.0/8)' }
 * validateUrl('http://localhost/secret')                    // { safe: false, reason: 'loopback address' }
 * validateUrl('file:///etc/passwd')                         // { safe: false, reason: 'disallowed protocol: file:' }
 *
 * // Allow safe URLs
 * validateUrl('https://api.example.com/data')               // { safe: true }
 */

/** Options for URL validation */
export interface ValidateUrlOptions {
  /** Allowed protocols. Default: ['http:', 'https:'] */
  allowedProtocols?: string[];
  /** Additional hostnames to block (e.g., internal service names) */
  blockedHosts?: string[];
  /** Additional hostnames to always allow (bypass IP checks) */
  allowedHosts?: string[];
  /** Allow localhost/loopback. Default: false */
  allowLocalhost?: boolean;
  /** Allow private/internal IPs. Default: false */
  allowPrivate?: boolean;
}

/** Result of URL validation */
export interface ValidateUrlResult {
  /** Whether the URL is safe to fetch */
  safe: boolean;
  /** Reason the URL was blocked (only set when safe=false) */
  reason?: string;
}

/**
 * Validate a URL for SSRF safety.
 *
 * Checks:
 * 1. Valid URL format
 * 2. Allowed protocol (default: http, https only)
 * 3. Not localhost/loopback (127.x.x.x, ::1, localhost)
 * 4. Not private IP (10.x, 172.16-31.x, 192.168.x)
 * 5. Not link-local (169.254.x.x — includes AWS/GCP/Azure metadata)
 * 6. Not blocked hostname
 * 7. No credentials in URL (user:pass@host)
 *
 * @param url - The URL string to validate
 * @param options - Validation options
 * @returns Validation result with safe flag and optional reason
 */
export function validateUrl(url: string, options: ValidateUrlOptions = {}): ValidateUrlResult {
  const {
    allowedProtocols = ['http:', 'https:'],
    blockedHosts = [],
    allowedHosts = [],
    allowLocalhost = false,
    allowPrivate = false,
  } = options;

  if (typeof url !== 'string' || url.trim() === '') {
    return { safe: false, reason: 'invalid URL: empty or not a string' };
  }

  // Parse URL
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { safe: false, reason: 'invalid URL: failed to parse' };
  }

  // Check protocol
  if (!allowedProtocols.includes(parsed.protocol)) {
    return { safe: false, reason: `disallowed protocol: ${parsed.protocol}` };
  }

  // Check for credentials in URL (user:pass@host)
  if (parsed.username || parsed.password) {
    return { safe: false, reason: 'URL contains credentials' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Check explicit allowlist first (bypass IP checks)
  if (allowedHosts.some(h => hostname === h.toLowerCase())) {
    return { safe: true };
  }

  // Check explicit blocklist
  if (blockedHosts.some(h => hostname === h.toLowerCase())) {
    return { safe: false, reason: `blocked host: ${hostname}` };
  }

  // Check localhost/loopback
  if (!allowLocalhost) {
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '[::1]' ||
      hostname === '::1' ||
      hostname === '0.0.0.0' ||
      hostname.endsWith('.localhost')
    ) {
      return { safe: false, reason: 'loopback address' };
    }

    // Check 127.x.x.x range
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      return { safe: false, reason: 'loopback address' };
    }
  }

  // Check private/internal IPs
  if (!allowPrivate) {
    const privateCheck = checkPrivateIp(hostname);
    if (privateCheck) {
      return { safe: false, reason: privateCheck };
    }
  }

  return { safe: true };
}

/**
 * Convenience wrapper that returns true/false.
 *
 * @param url - The URL to check
 * @param options - Validation options
 * @returns true if the URL is safe to fetch
 */
export function isUrlSafe(url: string, options: ValidateUrlOptions = {}): boolean {
  return validateUrl(url, options).safe;
}

/**
 * Check if a hostname is a private/internal IP address.
 * Returns the reason string if private, or null if not.
 */
function checkPrivateIp(hostname: string): string | null {
  // 10.0.0.0/8
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'private address (10.0.0.0/8)';
  }

  // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
  const match172 = hostname.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (match172) {
    const second = parseInt(match172[1], 10);
    if (second >= 16 && second <= 31) {
      return 'private address (172.16.0.0/12)';
    }
  }

  // 192.168.0.0/16
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'private address (192.168.0.0/16)';
  }

  // 169.254.0.0/16 — link-local, includes cloud metadata endpoints
  // AWS: 169.254.169.254, GCP: metadata.google.internal, Azure: 169.254.169.254
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'link-local address (169.254.0.0/16)';
  }

  // 0.0.0.0/8 (current network)
  if (/^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    return 'current network address (0.0.0.0/8)';
  }

  // Cloud metadata hostnames
  if (
    hostname === 'metadata.google.internal' ||
    hostname === 'metadata.internal'
  ) {
    return 'cloud metadata endpoint';
  }

  // IPv6 private ranges (simplified — bracket-wrapped in URLs)
  const ipv6 = hostname.replace(/^\[|\]$/g, '');
  if (
    ipv6 === '::1' ||
    ipv6 === '::' ||
    ipv6.startsWith('fc') ||
    ipv6.startsWith('fd') ||
    ipv6.startsWith('fe80')
  ) {
    return 'private IPv6 address';
  }

  return null;
}
