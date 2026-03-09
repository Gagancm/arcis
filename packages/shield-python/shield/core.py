"""
Shield Core - Main Shield class and components

This module provides the core security functionality for Python web frameworks.
"""

import re
import time
import json
import logging
import threading
import atexit
from typing import Any, Dict, List, Optional, Callable, Set, Union
from dataclasses import dataclass
from functools import wraps
from pathlib import Path

# Load patterns from core
PATTERNS_PATH = Path(__file__).parent.parent.parent / "core" / "patterns.json"

def load_patterns() -> Dict:
    """Load security patterns from core package."""
    try:
        with open(PATTERNS_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Fallback to embedded patterns
        return get_embedded_patterns()

def get_embedded_patterns() -> Dict:
    """Fallback embedded patterns if core not available."""
    return {
        "patterns": {
            "xss": {
                "rules": [
                    {"pattern": r"<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>", "flags": "gi"},
                    {"pattern": r"javascript:", "flags": "gi"},
                    {"pattern": r"vbscript:", "flags": "gi"},
                    {"pattern": r"on\w+\s*=", "flags": "gi"},
                    {"pattern": r"<iframe", "flags": "gi"},
                    {"pattern": r"<object", "flags": "gi"},
                    {"pattern": r"<embed", "flags": "gi"},
                    {"pattern": r"data:", "flags": "gi"},
                ],
                "encoding": {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}
            },
            "sql_injection": {
                "rules": [
                    {"pattern": r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b", "flags": "gi"},
                    {"pattern": r"(--|/\*|\*/)", "flags": "g"},
                    {"pattern": r"(;|\|\||&&)", "flags": "g"},
                    {"pattern": r"\bOR\s+\d+\s*=\s*\d+", "flags": "gi"},
                    {"pattern": r"\bAND\s+\d+\s*=\s*\d+", "flags": "gi"},
                ]
            },
            "nosql_injection": {
                "dangerous_keys": ["$gt", "$gte", "$lt", "$lte", "$ne", "$eq", "$in", "$nin", 
                                   "$and", "$or", "$not", "$exists", "$type", "$regex", "$where", "$expr"]
            },
            "path_traversal": {
                "rules": [
                    {"pattern": r"\.\./", "flags": "g"},
                    {"pattern": r"\.\.\\", "flags": "g"},
                    {"pattern": r"%2e%2e", "flags": "gi"},
                    {"pattern": r"%252e", "flags": "gi"},
                ]
            }
        },
        "security_headers": {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "X-Permitted-Cross-Domain-Policies": "none",
        },
        "sensitive_keys": ["password", "passwd", "pwd", "secret", "token", "apikey", "api_key", 
                          "authorization", "auth", "credit_card", "creditcard", "cc", "ssn",
                          "social_security", "private_key", "privateKey", "access_token",
                          "accessToken", "refresh_token", "refreshToken", "bearer", "jwt",
                          "session", "cookie"]
    }

PATTERNS = load_patterns()


# Constants
DEFAULT_MAX_INPUT_SIZE = 1_000_000  # 1MB
MAX_RECURSION_DEPTH = 10


@dataclass
class RateLimitEntry:
    """Rate limit entry for consistent API across Node.js, Go, and Python."""
    count: int
    reset_time: float


class InputTooLargeError(Exception):
    """Exception raised when input exceeds maximum size."""
    def __init__(self, size: int, max_size: int):
        self.size = size
        self.max_size = max_size
        super().__init__(f"Input size {size} exceeds maximum of {max_size} bytes")


class Sanitizer:
    """
    Input sanitizer that prevents XSS, SQL injection, NoSQL injection,
    path traversal, and command injection.
    
    Example:
        sanitizer = Sanitizer()
        safe_data = sanitizer(user_input)
    """
    
    def __init__(
        self,
        xss: bool = True,
        sql: bool = True,
        nosql: bool = True,
        path: bool = True,
        command: bool = True,
        max_input_size: int = DEFAULT_MAX_INPUT_SIZE,
    ):
        self.xss = xss
        self.sql = sql
        self.nosql = nosql
        self.path = path
        self.command = command
        self.max_input_size = max_input_size
        
        # Compile XSS patterns (ReDoS-safe)
        self._xss_patterns = []
        if "xss" in PATTERNS.get("patterns", {}):
            for rule in PATTERNS["patterns"]["xss"].get("rules", []):
                flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
                self._xss_patterns.append(re.compile(rule["pattern"], flags))
        
        # Compile SQL patterns
        self._sql_patterns = []
        if "sql_injection" in PATTERNS.get("patterns", {}):
            for rule in PATTERNS["patterns"]["sql_injection"].get("rules", []):
                flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
                self._sql_patterns.append(re.compile(rule["pattern"], flags))
        
        # NoSQL dangerous keys
        self._nosql_keys: Set[str] = set()
        if "nosql_injection" in PATTERNS.get("patterns", {}):
            self._nosql_keys = set(PATTERNS["patterns"]["nosql_injection"].get("dangerous_keys", []))
        
        # Prototype pollution dangerous keys
        self._proto_keys: Set[str] = {"__proto__", "constructor", "prototype"}
        
        # Path traversal patterns
        self._path_patterns = []
        if "path_traversal" in PATTERNS.get("patterns", {}):
            for rule in PATTERNS["patterns"]["path_traversal"].get("rules", []):
                flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
                self._path_patterns.append(re.compile(rule["pattern"], flags))
        
        # Command injection patterns
        self._command_patterns = []
        if command:
            self._command_patterns = [
                re.compile(r'[;&|`$()]'),
                re.compile(r'\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php)\b', re.IGNORECASE),
            ]
        
        # XSS encoding map
        self._xss_encoding = PATTERNS.get("patterns", {}).get("xss", {}).get("encoding", {
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"
        })
    
    def sanitize_string(self, value: str) -> str:
        """Sanitize a string value."""
        if not isinstance(value, str):
            return value
        
        # Input size limit to prevent DoS
        if len(value) > self.max_input_size:
            raise InputTooLargeError(len(value), self.max_input_size)
        
        result = value
        
        # XSS prevention - remove patterns FIRST (while detectable), then encode
        if self.xss:
            # Remove dangerous patterns FIRST
            for pattern in self._xss_patterns:
                result = pattern.sub("", result)
            
            # THEN encode remaining content
            for char, replacement in self._xss_encoding.items():
                result = result.replace(char, replacement)
        
        # SQL injection prevention
        if self.sql:
            for pattern in self._sql_patterns:
                result = pattern.sub("[BLOCKED]", result)
        
        # Path traversal prevention
        if self.path:
            for pattern in self._path_patterns:
                result = pattern.sub("", result)
        
        # Command injection prevention
        if self.command:
            for pattern in self._command_patterns:
                result = pattern.sub("[BLOCKED]", result)
        
        return result
    
    def sanitize_dict(self, data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        """Sanitize a dictionary, including nested structures."""
        if depth > MAX_RECURSION_DEPTH:
            return data
        
        if not isinstance(data, dict):
            if isinstance(data, str):
                return self.sanitize_string(data)
            elif isinstance(data, list):
                return [self.sanitize_dict(item, depth + 1) for item in data]
            return data
        
        result = {}
        for key, value in data.items():
            # Prototype pollution prevention - always block dangerous keys
            if key in self._proto_keys:
                continue
            
            # NoSQL injection prevention - skip dangerous keys
            if self.nosql and key in self._nosql_keys:
                continue
            
            # Sanitize the key
            sanitized_key = self.sanitize_string(key) if isinstance(key, str) else key
            
            # Recursively sanitize value
            if isinstance(value, dict):
                result[sanitized_key] = self.sanitize_dict(value, depth + 1)
            elif isinstance(value, list):
                result[sanitized_key] = [self.sanitize_dict(item, depth + 1) for item in value]
            elif isinstance(value, str):
                result[sanitized_key] = self.sanitize_string(value)
            else:
                result[sanitized_key] = value
        
        return result
    
    def __call__(self, data: Any) -> Any:
        """Make sanitizer callable."""
        if isinstance(data, dict):
            return self.sanitize_dict(data)
        elif isinstance(data, str):
            return self.sanitize_string(data)
        elif isinstance(data, list):
            return [self(item) for item in data]
        return data


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 0):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


class InMemoryStore:
    """Thread-safe in-memory store for rate limiting."""
    def __init__(self):
        self._store: Dict[str, RateLimitEntry] = {}
        self._lock = threading.Lock()
        self._closed = False
    
    def get(self, key: str) -> Optional[RateLimitEntry]:
        with self._lock:
            entry = self._store.get(key)
            if entry and entry.reset_time < time.time():
                del self._store[key]
                return None
            return entry
    
    def set(self, key: str, count: int, reset_time: float):
        with self._lock:
            self._store[key] = RateLimitEntry(count=count, reset_time=reset_time)
    
    def increment(self, key: str) -> int:
        with self._lock:
            entry = self._store.get(key)
            if entry:
                entry.count += 1
                return entry.count
            return 1
    
    def cleanup(self):
        """Remove expired entries."""
        with self._lock:
            now = time.time()
            expired = [k for k, v in self._store.items() if v.reset_time < now]
            for k in expired:
                del self._store[k]
    
    def clear(self):
        """Clear all entries."""
        with self._lock:
            self._store.clear()
    
    def close(self):
        """Mark store as closed."""
        self._closed = True
        self.clear()


class RateLimiter:
    """
    Rate limiter with configurable limits and window sizes.
    
    Example:
        limiter = RateLimiter(max_requests=100, window_ms=60000)
        try:
            result = limiter.check(request)
        except RateLimitExceeded as e:
            return error_response(e.message, e.retry_after)
    """
    
    def __init__(
        self,
        max_requests: int = 100,
        window_ms: int = 60000,
        message: str = "Too many requests, please try again later.",
        key_func: Optional[Callable] = None,
        skip_func: Optional[Callable] = None,
        store: Optional[InMemoryStore] = None,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_ms / 1000
        self.message = message
        self.key_func = key_func or self._default_key_func
        self.skip_func = skip_func
        self.store = store or InMemoryStore()
        self._closed = False
        
        # Start cleanup thread
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_event = threading.Event()
        self._start_cleanup_thread()
        
        # Register cleanup on exit
        atexit.register(self.close)
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread."""
        def cleanup_loop():
            while not self._cleanup_event.wait(timeout=self.window_seconds):
                if self._closed:
                    break
                self.store.cleanup()
        
        self._cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def close(self):
        """Stop cleanup thread and release resources."""
        if self._closed:
            return
        self._closed = True
        self._cleanup_event.set()
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1.0)
        self.store.close()
    
    def _default_key_func(self, request) -> str:
        """Default key function - uses IP address."""
        # Works with Flask, FastAPI, Django
        if hasattr(request, 'remote_addr'):
            return request.remote_addr or "unknown"
        if hasattr(request, 'client'):
            return request.client.host if request.client else "unknown"
        if hasattr(request, 'META'):
            return request.META.get('REMOTE_ADDR', 'unknown')
        return "unknown"
    
    def check(self, request) -> Dict[str, Any]:
        """
        Check if request is within rate limit.
        Returns dict with limit info and raises RateLimitExceeded if exceeded.
        """
        if self._closed:
            # Fail open if closed
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests}
        
        if self.skip_func and self.skip_func(request):
            return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests}
        
        key = self.key_func(request)
        now = time.time()
        
        entry = self.store.get(key)
        
        if not entry:
            self.store.set(key, 1, now + self.window_seconds)
            return {
                "allowed": True,
                "limit": self.max_requests,
                "remaining": self.max_requests - 1,
                "reset": int(self.window_seconds),
            }
        
        count = self.store.increment(key)
        remaining = max(0, self.max_requests - count)
        reset = int(entry.reset_time - now)
        
        if count > self.max_requests:
            raise RateLimitExceeded(self.message, reset)
        
        return {
            "allowed": True,
            "limit": self.max_requests,
            "remaining": remaining,
            "reset": reset,
        }


class SecurityHeaders:
    """
    Security headers middleware component.
    
    Example:
        headers = SecurityHeaders(content_security_policy="default-src 'self'")
        headers.apply(response)
    """
    
    DEFAULT_HEADERS = PATTERNS.get("security_headers", {})
    
    def __init__(
        self,
        content_security_policy: Optional[str] = None,
        x_frame_options: str = "DENY",
        x_content_type_options: str = "nosniff",
        xss_filter: bool = True,
        hsts: bool = True,
        hsts_max_age: int = 31536000,
        hsts_include_subdomains: bool = True,
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: str = "geolocation=(), microphone=(), camera=()",
        cache_control: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        self.headers = dict(self.DEFAULT_HEADERS)
        
        if content_security_policy:
            self.headers["Content-Security-Policy"] = content_security_policy
        
        if x_frame_options:
            self.headers["X-Frame-Options"] = x_frame_options
        
        if x_content_type_options:
            self.headers["X-Content-Type-Options"] = x_content_type_options
        
        if xss_filter:
            self.headers["X-XSS-Protection"] = "1; mode=block"
        
        if hsts:
            hsts_value = f"max-age={hsts_max_age}"
            if hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            self.headers["Strict-Transport-Security"] = hsts_value
        
        if referrer_policy:
            self.headers["Referrer-Policy"] = referrer_policy
        
        if permissions_policy:
            self.headers["Permissions-Policy"] = permissions_policy
        
        # Cache-Control headers to prevent caching of sensitive data
        if cache_control:
            self.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
            self.headers["Pragma"] = "no-cache"
            self.headers["Expires"] = "0"
        
        self.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        
        if custom_headers:
            self.headers.update(custom_headers)
    
    def apply(self, response) -> None:
        """Apply security headers to a response object."""
        for header, value in self.headers.items():
            if hasattr(response, 'headers'):
                response.headers[header] = value
            elif hasattr(response, '__setitem__'):
                response[header] = value
    
    def get_headers(self) -> Dict[str, str]:
        """Get all security headers as a dict."""
        return dict(self.headers)


class Validator:
    """
    Input validator with common validation rules.
    
    Example:
        if not Validator.email(user_input):
            raise ValidationError(["Invalid email format"])
    """
    
    EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")
    UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
    
    @classmethod
    def email(cls, value: str) -> bool:
        """Validate email format."""
        return bool(cls.EMAIL_PATTERN.match(value))
    
    @classmethod
    def url(cls, value: str) -> bool:
        """Validate URL format."""
        return bool(cls.URL_PATTERN.match(value))
    
    @classmethod
    def uuid(cls, value: str) -> bool:
        """Validate UUID format."""
        return bool(cls.UUID_PATTERN.match(value))
    
    @classmethod
    def length(cls, value: str, min_len: int = 0, max_len: Optional[int] = None) -> bool:
        """Validate string length."""
        if len(value) < min_len:
            return False
        if max_len is not None and len(value) > max_len:
            return False
        return True
    
    @classmethod
    def number_range(cls, value: float, min_val: Optional[float] = None, max_val: Optional[float] = None) -> bool:
        """Validate number range."""
        if min_val is not None and value < min_val:
            return False
        if max_val is not None and value > max_val:
            return False
        return True


class ValidationError(Exception):
    """Exception raised when validation fails."""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(", ".join(errors))


# ============================================
# SCHEMA VALIDATION (like Node.js validate())
# ============================================

class SchemaValidator:
    """
    Schema-based validator with mass assignment prevention.
    
    Example:
        schema = {
            'email': {'type': 'email', 'required': True},
            'age': {'type': 'number', 'min': 0, 'max': 150},
            'role': {'type': 'string', 'enum': ['user', 'admin']}
        }
        validator = SchemaValidator(schema)
        validated_data, errors = validator.validate(request_data)
    """
    
    def __init__(self, schema: Dict[str, Dict[str, Any]], sanitize: bool = True):
        self.schema = schema
        self.sanitizer = Sanitizer() if sanitize else None
    
    def validate(self, data: Dict[str, Any]) -> tuple:
        """
        Validate data against schema.
        Returns (validated_data, errors) tuple.
        Only fields in schema are returned (mass assignment prevention).
        """
        errors: List[str] = []
        validated: Dict[str, Any] = {}
        
        for field, rules in self.schema.items():
            value = data.get(field)
            
            # Required check
            if rules.get('required') and (value is None or value == ''):
                errors.append(f"{field} is required")
                continue
            
            # Skip optional empty fields
            if value is None:
                continue
            
            typed_value = value
            is_valid = True
            field_type = rules.get('type', 'string')
            
            # Type validation and coercion
            if field_type == 'string':
                if not isinstance(value, str):
                    errors.append(f"{field} must be a string")
                    is_valid = False
                else:
                    min_len = rules.get('min')
                    max_len = rules.get('max')
                    if min_len is not None and len(value) < min_len:
                        errors.append(f"{field} must be at least {min_len} characters")
                        is_valid = False
                    if max_len is not None and len(value) > max_len:
                        errors.append(f"{field} must be at most {max_len} characters")
                        is_valid = False
                    pattern = rules.get('pattern')
                    if pattern and not re.match(pattern, value):
                        errors.append(f"{field} format is invalid")
                        is_valid = False
                    if is_valid and self.sanitizer and rules.get('sanitize', True):
                        typed_value = self.sanitizer.sanitize_string(value)
            
            elif field_type == 'number':
                try:
                    typed_value = float(value) if '.' in str(value) else int(value)
                except (ValueError, TypeError):
                    errors.append(f"{field} must be a number")
                    is_valid = False
                else:
                    min_val = rules.get('min')
                    max_val = rules.get('max')
                    if min_val is not None and typed_value < min_val:
                        errors.append(f"{field} must be at least {min_val}")
                        is_valid = False
                    if max_val is not None and typed_value > max_val:
                        errors.append(f"{field} must be at most {max_val}")
                        is_valid = False
            
            elif field_type == 'boolean':
                if value in (True, 'true', '1', 1):
                    typed_value = True
                elif value in (False, 'false', '0', 0):
                    typed_value = False
                else:
                    errors.append(f"{field} must be a boolean")
                    is_valid = False
            
            elif field_type == 'email':
                if not Validator.email(str(value)):
                    errors.append(f"{field} must be a valid email")
                    is_valid = False
                else:
                    typed_value = str(value).lower().strip()
                    if self.sanitizer:
                        typed_value = self.sanitizer.sanitize_string(typed_value)
            
            elif field_type == 'url':
                if not Validator.url(str(value)):
                    errors.append(f"{field} must be a valid URL")
                    is_valid = False
                elif self.sanitizer:
                    typed_value = self.sanitizer.sanitize_string(str(value))
            
            elif field_type == 'uuid':
                if not Validator.uuid(str(value)):
                    errors.append(f"{field} must be a valid UUID")
                    is_valid = False
            
            elif field_type == 'array':
                if not isinstance(value, list):
                    errors.append(f"{field} must be an array")
                    is_valid = False
                else:
                    min_len = rules.get('min')
                    max_len = rules.get('max')
                    if min_len is not None and len(value) < min_len:
                        errors.append(f"{field} must have at least {min_len} items")
                        is_valid = False
                    if max_len is not None and len(value) > max_len:
                        errors.append(f"{field} must have at most {max_len} items")
                        is_valid = False
            
            elif field_type == 'object':
                if not isinstance(value, dict):
                    errors.append(f"{field} must be an object")
                    is_valid = False
            
            # Enum validation
            enum_values = rules.get('enum')
            if is_valid and enum_values and typed_value not in enum_values:
                errors.append(f"{field} must be one of: {', '.join(map(str, enum_values))}")
                is_valid = False
            
            # Custom validation function
            custom = rules.get('custom')
            if is_valid and custom and callable(custom):
                custom_result = custom(typed_value)
                if custom_result is not True:
                    error_msg = custom_result if isinstance(custom_result, str) else f"{field} is invalid"
                    errors.append(error_msg)
                    is_valid = False
            
            if is_valid:
                validated[field] = typed_value
        
        return validated, errors


def create_validator(schema: Dict[str, Dict[str, Any]], sanitize: bool = True):
    """
    Create a schema validator function.
    
    Example:
        validate_user = create_validator({
            'email': {'type': 'email', 'required': True},
            'name': {'type': 'string', 'min': 2, 'max': 50},
        })
        validated, errors = validate_user(request.json)
    """
    validator = SchemaValidator(schema, sanitize)
    return validator.validate


# ============================================
# SAFE LOGGER
# ============================================

class SafeLogger:
    """
    Safe logger that redacts sensitive information and prevents log injection.
    
    Example:
        logger = SafeLogger()
        logger.info("User login", {"email": "test@test.com", "password": "secret"})
        # Output: {"timestamp": "...", "level": "info", "message": "User login", "data": {"email": "test@test.com", "password": "[REDACTED]"}}
    """
    
    SENSITIVE_KEYS: Set[str] = set(k.lower() for k in PATTERNS.get("sensitive_keys", []))
    
    def __init__(
        self,
        name: str = "shield",
        redact_keys: Optional[List[str]] = None,
        max_length: int = 10000,
    ):
        self.logger = logging.getLogger(name)
        self.max_length = max_length
        
        if redact_keys:
            self.sensitive_keys = self.SENSITIVE_KEYS | set(k.lower() for k in redact_keys)
        else:
            self.sensitive_keys = self.SENSITIVE_KEYS
    
    def _redact(self, data: Any, depth: int = 0) -> Any:
        """Redact sensitive data."""
        if depth > MAX_RECURSION_DEPTH:
            return "[MAX_DEPTH]"
        
        if isinstance(data, str):
            # Remove control characters (log injection prevention)
            safe = re.sub(r'[\r\n\t]', ' ', data)
            safe = re.sub(r'[^\x20-\x7E\u00A0-\u024F]', '', safe)
            if len(safe) > self.max_length:
                safe = safe[:self.max_length] + "...[TRUNCATED]"
            return safe
        
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if str(key).lower() in self.sensitive_keys:
                    result[key] = "[REDACTED]"
                else:
                    result[key] = self._redact(value, depth + 1)
            return result
        
        if isinstance(data, list):
            return [self._redact(item, depth + 1) for item in data]
        
        return data
    
    def _log(self, level: str, message: str, data: Optional[Dict] = None):
        """Internal log method."""
        import datetime
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "level": level,
            "message": self._redact(message),
        }
        if data is not None:
            entry["data"] = self._redact(data)
        
        log_line = json.dumps(entry)
        getattr(self.logger, level)(log_line)
    
    def info(self, message: str, data: Optional[Dict] = None):
        """Log info message with redacted data."""
        self._log("info", message, data)
    
    def warning(self, message: str, data: Optional[Dict] = None):
        """Log warning message with redacted data."""
        self._log("warning", message, data)
    
    def warn(self, message: str, data: Optional[Dict] = None):
        """Alias for warning."""
        self.warning(message, data)
    
    def error(self, message: str, data: Optional[Dict] = None):
        """Log error message with redacted data."""
        self._log("error", message, data)
    
    def debug(self, message: str, data: Optional[Dict] = None):
        """Log debug message with redacted data."""
        self._log("debug", message, data)


# ============================================
# ERROR HANDLER (like Node.js errorHandler())
# ============================================

class ErrorHandler:
    """
    Production-safe error handler that hides sensitive details.
    
    Example:
        handler = ErrorHandler(is_dev=False)
        response = handler.handle(exception, status_code=500)
    """
    
    def __init__(self, is_dev: bool = False, logger: Optional[SafeLogger] = None):
        self.is_dev = is_dev
        self.logger = logger
    
    def handle(self, error: Exception, status_code: int = 500) -> Dict[str, Any]:
        """
        Handle an error and return a safe response dict.
        In production, hides error details for 5xx errors.
        """
        # Log the error if logger provided
        if self.logger:
            self.logger.error("Request error", {
                "error": str(error),
                "status_code": status_code,
            })
        
        response: Dict[str, Any] = {}
        
        if status_code >= 500:
            response["error"] = "Internal Server Error"
        else:
            response["error"] = str(error)
        
        # Only show details in development
        if self.is_dev:
            response["details"] = str(error)
            import traceback
            response["stack"] = traceback.format_exc()
        
        return response
    
    def flask_handler(self, error: Exception):
        """Flask error handler."""
        from flask import jsonify
        status_code = getattr(error, 'code', 500) or 500
        response = jsonify(self.handle(error, status_code))
        response.status_code = status_code
        return response


def create_error_handler(is_dev: bool = False, logger: Optional[SafeLogger] = None) -> ErrorHandler:
    """
    Create an error handler.
    
    Example:
        handler = create_error_handler(is_dev=os.environ.get('FLASK_ENV') == 'development')
    """
    return ErrorHandler(is_dev=is_dev, logger=logger)


# ============================================
# MAIN SHIELD CLASS
# ============================================

class Shield:
    """
    Main Shield class - one-line security for Python web frameworks.
    
    Usage:
        # Flask
        from shield import Shield
        Shield(app)
        
        # Or configure:
        Shield(app, rate_limit_max=50, sanitize_sql=False)
    """
    
    def __init__(
        self,
        app=None,
        # Sanitizer options
        sanitize: bool = True,
        sanitize_xss: bool = True,
        sanitize_sql: bool = True,
        sanitize_nosql: bool = True,
        sanitize_path: bool = True,
        # Rate limiter options
        rate_limit: bool = True,
        rate_limit_max: int = 100,
        rate_limit_window_ms: int = 60000,
        # Security headers options
        headers: bool = True,
        csp: Optional[str] = None,
        # Logger
        safe_logging: bool = True,
        # Error handler
        error_handler: bool = True,
        is_dev: bool = False,
    ):
        self.sanitizer = Sanitizer(
            xss=sanitize_xss,
            sql=sanitize_sql,
            nosql=sanitize_nosql,
            path=sanitize_path,
        ) if sanitize else None
        
        self.rate_limiter = RateLimiter(
            max_requests=rate_limit_max,
            window_ms=rate_limit_window_ms,
        ) if rate_limit else None
        
        self.security_headers = SecurityHeaders(
            content_security_policy=csp,
        ) if headers else None
        
        self.logger = SafeLogger() if safe_logging else None
        
        self.error_handler = ErrorHandler(
            is_dev=is_dev,
            logger=self.logger,
        ) if error_handler else None
        
        self._app = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Shield with a Flask or similar app."""
        self._app = app
        
        # Detect framework
        app_type = type(app).__name__
        
        if app_type == "Flask" or hasattr(app, 'before_request'):
            self._init_flask(app)
        elif app_type == "FastAPI" or hasattr(app, 'add_middleware'):
            self._init_fastapi(app)
        else:
            raise ValueError(f"Unsupported framework: {app_type}")
    
    def close(self):
        """Clean up resources. Call this when shutting down."""
        if self.rate_limiter:
            self.rate_limiter.close()
    
    def _init_flask(self, app):
        """Initialize for Flask."""
        from flask import request, g
        
        @app.before_request
        def shield_before_request():
            # Rate limiting
            if self.rate_limiter:
                try:
                    result = self.rate_limiter.check(request)
                    g.rate_limit_info = result
                except RateLimitExceeded as e:
                    from flask import jsonify
                    response = jsonify({"error": e.message, "retry_after": e.retry_after})
                    response.status_code = 429
                    response.headers['Retry-After'] = str(e.retry_after)
                    return response
            
            # Sanitize request data
            if self.sanitizer:
                if request.is_json and request.json:
                    # Flask's request.json is immutable, store sanitized data in g
                    g.sanitized_json = self.sanitizer(request.json)
                    # Also make it accessible as g.json for convenience
                    g.json = g.sanitized_json
        
        @app.after_request
        def shield_after_request(response):
            # Add security headers
            if self.security_headers:
                self.security_headers.apply(response)
            
            # Add rate limit headers
            if hasattr(g, 'rate_limit_info'):
                info = g.rate_limit_info
                response.headers['X-RateLimit-Limit'] = str(info['limit'])
                response.headers['X-RateLimit-Remaining'] = str(info['remaining'])
                response.headers['X-RateLimit-Reset'] = str(info['reset'])
            
            # Remove fingerprinting headers
            response.headers.pop('Server', None)
            response.headers.pop('X-Powered-By', None)
            
            return response
        
        # Register error handler
        if self.error_handler:
            @app.errorhandler(Exception)
            def handle_exception(e):
                return self.error_handler.flask_handler(e)
    
    def _init_fastapi(self, app):
        """Initialize for FastAPI."""
        from .fastapi import ShieldMiddleware
        app.add_middleware(
            ShieldMiddleware,
            sanitizer=self.sanitizer,
            rate_limiter=self.rate_limiter,
            security_headers=self.security_headers,
            error_handler=self.error_handler,
        )


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def sanitize_string(value: str, **options) -> str:
    """Sanitize a single string."""
    return Sanitizer(**options).sanitize_string(value)

def sanitize_dict(data: Dict, **options) -> Dict:
    """Sanitize a dictionary."""
    return Sanitizer(**options).sanitize_dict(data)

def validate_email(value: str) -> bool:
    """Validate email format."""
    return Validator.email(value)

def validate_url(value: str) -> bool:
    """Validate URL format."""
    return Validator.url(value)

def validate_uuid(value: str) -> bool:
    """Validate UUID format."""
    return Validator.uuid(value)
