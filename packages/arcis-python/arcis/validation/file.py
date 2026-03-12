"""
Arcis Validation - File Upload

Validates file uploads and sanitizes filenames.
Prevents unrestricted upload, executable upload, MIME bypass, and path traversal via filenames.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

# =============================================================================
# MAGIC BYTES — first bytes of common file types
# =============================================================================

MAGIC_BYTES: Dict[str, List[bytes]] = {
    # Images
    "image/jpeg": [b"\xFF\xD8\xFF"],
    "image/png": [b"\x89PNG"],
    "image/gif": [b"GIF87a", b"GIF89a"],
    "image/webp": [b"RIFF"],  # RIFF....WEBP
    "image/bmp": [b"BM"],
    "image/svg+xml": [],  # text-based, check separately

    # Documents
    "application/pdf": [b"%PDF"],
    "application/zip": [b"PK\x03\x04"],

    # Audio/Video
    "audio/mpeg": [b"\xFF\xFB", b"\xFF\xF3", b"ID3"],
}

# =============================================================================
# DANGEROUS EXTENSIONS — files that can execute code
# =============================================================================

DANGEROUS_EXTENSIONS: Set[str] = {
    # Scripts
    ".exe", ".bat", ".cmd", ".com", ".msi", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh",
    ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2",
    ".sh", ".bash", ".csh", ".ksh",
    # Server-side
    ".php", ".php3", ".php4", ".php5", ".phtml", ".pht",
    ".asp", ".aspx", ".ashx", ".asmx", ".cer",
    ".jsp", ".jspx", ".jsw", ".jsv",
    ".cgi", ".pl", ".py", ".rb",
    # Java
    ".jar", ".war", ".ear", ".class",
    # Config that can execute
    ".htaccess", ".htpasswd",
    # Template engines
    ".ejs", ".pug", ".hbs", ".handlebars", ".njk", ".twig",
    # Shortcuts/links
    ".lnk", ".inf", ".reg", ".url",
    # Office macros
    ".docm", ".xlsm", ".pptm", ".dotm",
}

DEFAULT_MAX_SIZE = 5 * 1024 * 1024  # 5MB


# =============================================================================
# TYPES
# =============================================================================

@dataclass
class ValidateFileResult:
    """Result of file validation."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    sanitized_filename: str = ""


# =============================================================================
# FILENAME SANITIZATION
# =============================================================================

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe storage.

    Strips path traversal, null bytes, control characters, and special characters.

    Example:
        sanitize_filename('../../etc/passwd')    # 'etc_passwd'
        sanitize_filename('file<name>.jpg')      # 'filename.jpg'
        sanitize_filename('.htaccess')            # 'htaccess'
    """
    name = filename

    # Strip null bytes
    name = name.replace("\0", "")

    # Strip path components (both Unix and Windows)
    name = re.sub(r"^.*[/\\]", "", name)

    # Strip control characters
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)

    # Strip characters unsafe for filesystems
    name = re.sub(r'[<>:"/\\|?*]', "", name)

    # Replace spaces and parens with underscores
    name = re.sub(r"[\s()]+", "_", name)

    # Strip leading dots (hidden files / .htaccess)
    name = re.sub(r"^\.+", "", name)

    # Collapse multiple underscores/dots
    name = re.sub(r"_{2,}", "_", name)
    name = re.sub(r"\.{2,}", ".", name)

    # Trim underscores before dots (e.g., "photo_1_.jpg" → "photo_1.jpg")
    name = re.sub(r"_+\.", ".", name)

    # Trim underscores from edges
    name = name.strip("_")

    # Fallback for empty name
    if not name or name == ".":
        name = "unnamed"

    return name


# =============================================================================
# HELPERS
# =============================================================================

def _get_extension(filename: str) -> str:
    """Get the extension from a filename (lowercase, with dot)."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _has_double_extension(filename: str) -> bool:
    """Check if a filename has double extensions with a dangerous inner extension."""
    parts = filename.split(".")
    if len(parts) < 3:
        return False
    for part in parts[1:-1]:
        ext = "." + part.lower()
        if ext in DANGEROUS_EXTENSIONS:
            return True
    return False


def _matches_magic_bytes(content: bytes, mimetype: str) -> bool:
    """Check if file content matches the claimed MIME type via magic bytes."""
    signatures = MAGIC_BYTES.get(mimetype)
    if signatures is None or len(signatures) == 0:
        return True  # no signature to check

    return any(
        len(content) >= len(sig) and content[:len(sig)] == sig
        for sig in signatures
    )


def is_dangerous_extension(filename: str) -> bool:
    """
    Check if a file extension is considered dangerous/executable.

    Args:
        filename: Filename or extension to check

    Returns:
        True if the extension is dangerous
    """
    ext = _get_extension(filename)
    return ext != "" and ext in DANGEROUS_EXTENSIONS


# =============================================================================
# FILE VALIDATION
# =============================================================================

def validate_file(
    filename: str,
    mimetype: str,
    size: int,
    content: Optional[bytes] = None,
    *,
    max_size: int = DEFAULT_MAX_SIZE,
    allowed_types: Optional[Sequence[str]] = None,
    allowed_extensions: Optional[Sequence[str]] = None,
    block_executables: bool = True,
    validate_magic_bytes: bool = True,
    block_no_extension: bool = True,
    block_double_extensions: bool = True,
) -> ValidateFileResult:
    """
    Validate a file upload for security.

    Args:
        filename: Original filename
        mimetype: MIME type (as claimed by client)
        size: File size in bytes
        content: File content bytes (for magic byte validation)
        max_size: Maximum file size in bytes. Default: 5MB
        allowed_types: Whitelist of MIME types
        allowed_extensions: Whitelist of extensions (with dot)
        block_executables: Block dangerous extensions. Default: True
        validate_magic_bytes: Validate magic bytes. Default: True
        block_no_extension: Block files with no extension. Default: True
        block_double_extensions: Block double extensions. Default: True

    Returns:
        ValidateFileResult with errors and sanitized filename

    Example:
        result = validate_file(
            "photo.jpg", "image/jpeg", 1024, content,
            allowed_types=["image/jpeg", "image/png"],
        )
        if not result.valid:
            return {"errors": result.errors}, 400
    """
    errors: List[str] = []
    sanitized = sanitize_filename(filename)
    extension = _get_extension(sanitized)

    # Size check
    if size > max_size:
        errors.append(f"File size {size} exceeds maximum {max_size} bytes")

    if size == 0:
        errors.append("File is empty")

    # Extension checks
    if block_no_extension and not extension:
        errors.append("File has no extension")

    if block_executables and extension and extension in DANGEROUS_EXTENSIONS:
        errors.append(f'Executable extension "{extension}" is not allowed')

    if block_double_extensions and _has_double_extension(sanitized):
        errors.append("Double extensions with executable types are not allowed")

    if allowed_extensions and extension:
        normalized = [e.lower() for e in allowed_extensions]
        if extension not in normalized:
            errors.append(
                f'Extension "{extension}" is not allowed. Allowed: {", ".join(normalized)}'
            )

    # MIME type check
    if allowed_types and mimetype not in allowed_types:
        errors.append(
            f'MIME type "{mimetype}" is not allowed. Allowed: {", ".join(allowed_types)}'
        )

    # Magic bytes validation
    if validate_magic_bytes and content and len(content) > 0:
        if not _matches_magic_bytes(content, mimetype):
            errors.append(f'File content does not match claimed MIME type "{mimetype}"')

    return ValidateFileResult(
        valid=len(errors) == 0,
        errors=errors,
        sanitized_filename=sanitized,
    )
