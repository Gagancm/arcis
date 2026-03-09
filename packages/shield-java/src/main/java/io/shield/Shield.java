package io.shield;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Shield Security Library for Java
 * 
 * One-line security for Java web applications providing:
 * - Input sanitization (XSS, SQL, NoSQL, Path traversal)
 * - Rate limiting with configurable windows
 * - Security headers
 * - Request validation
 * - Safe logging with redaction
 * - Production-safe error handling
 * 
 * Usage with Spring:
 * <pre>
 *     @Configuration
 *     public class SecurityConfig {
 *         @Bean
 *         public FilterRegistrationBean<ShieldFilter> shieldFilter() {
 *             FilterRegistrationBean<ShieldFilter> reg = new FilterRegistrationBean<>();
 *             reg.setFilter(new ShieldFilter());
 *             reg.addUrlPatterns("/*");
 *             return reg;
 *         }
 *     }
 * </pre>
 * 
 * Usage standalone:
 * <pre>
 *     Shield shield = Shield.create();
 *     String clean = shield.sanitize().sanitizeString(userInput);
 * </pre>
 */
public class Shield {
    
    private final Sanitizer sanitizer;
    private final RateLimiter rateLimiter;
    private final SecurityHeaders securityHeaders;
    private final Validator validator;
    private final SafeLogger logger;
    private final ErrorHandler errorHandler;
    
    private Shield(Builder builder) {
        this.sanitizer = builder.sanitizer != null ? builder.sanitizer : new Sanitizer();
        this.rateLimiter = builder.rateLimiter != null ? builder.rateLimiter : new RateLimiter();
        this.securityHeaders = builder.securityHeaders != null ? builder.securityHeaders : new SecurityHeaders();
        this.validator = builder.validator != null ? builder.validator : new Validator();
        this.logger = builder.logger != null ? builder.logger : new SafeLogger();
        this.errorHandler = builder.errorHandler != null ? builder.errorHandler : new ErrorHandler(false);
    }
    
    public static Shield create() {
        return new Builder().build();
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public Sanitizer sanitize() { return sanitizer; }
    public RateLimiter rateLimit() { return rateLimiter; }
    public SecurityHeaders headers() { return securityHeaders; }
    public Validator validate() { return validator; }
    public SafeLogger logger() { return logger; }
    public ErrorHandler errorHandler() { return errorHandler; }
    
    public void close() {
        rateLimiter.close();
    }
    
    // ========================================================================
    // BUILDER
    // ========================================================================
    
    public static class Builder {
        private Sanitizer sanitizer;
        private RateLimiter rateLimiter;
        private SecurityHeaders securityHeaders;
        private Validator validator;
        private SafeLogger logger;
        private ErrorHandler errorHandler;
        
        public Builder sanitizer(Sanitizer sanitizer) {
            this.sanitizer = sanitizer;
            return this;
        }
        
        public Builder rateLimiter(RateLimiter rateLimiter) {
            this.rateLimiter = rateLimiter;
            return this;
        }
        
        public Builder securityHeaders(SecurityHeaders headers) {
            this.securityHeaders = headers;
            return this;
        }
        
        public Builder validator(Validator validator) {
            this.validator = validator;
            return this;
        }
        
        public Builder logger(SafeLogger logger) {
            this.logger = logger;
            return this;
        }
        
        public Builder errorHandler(ErrorHandler errorHandler) {
            this.errorHandler = errorHandler;
            return this;
        }
        
        public Shield build() {
            return new Shield(this);
        }
    }
    
    // ========================================================================
    // SANITIZER
    // ========================================================================
    
    public static class Sanitizer {
        
        private static final Pattern XSS_SCRIPT = Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        private static final Pattern XSS_JAVASCRIPT = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
        private static final Pattern XSS_ON_EVENT = Pattern.compile("\\s+on\\w+\\s*=", Pattern.CASE_INSENSITIVE);
        private static final Pattern XSS_DANGEROUS_TAGS = Pattern.compile("<(iframe|object|embed|form|input)[^>]*>", Pattern.CASE_INSENSITIVE);
        
        private static final Pattern SQL_KEYWORDS = Pattern.compile(
            "\\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\\b",
            Pattern.CASE_INSENSITIVE
        );
        private static final Pattern SQL_COMMENTS = Pattern.compile("(--|/\\*|\\*/|;\\s*$)");
        
        private static final Pattern PATH_TRAVERSAL = Pattern.compile("(\\.\\./|\\.\\.\\\\/|%2e%2e|%252e)", Pattern.CASE_INSENSITIVE);
        
        private static final Set<String> NOSQL_OPERATORS = Set.of(
            "$gt", "$gte", "$lt", "$lte", "$ne", "$eq",
            "$in", "$nin", "$and", "$or", "$not",
            "$exists", "$type", "$regex", "$where", "$expr"
        );
        
        private static final Set<String> PROTO_KEYS = Set.of(
            "__proto__", "constructor", "prototype"
        );
        
        private boolean xss = true;
        private boolean sql = true;
        private boolean nosql = true;
        private boolean path = true;
        private boolean proto = true;
        
        public Sanitizer() {}
        
        public Sanitizer(boolean xss, boolean sql, boolean nosql, boolean path, boolean proto) {
            this.xss = xss;
            this.sql = sql;
            this.nosql = nosql;
            this.path = path;
            this.proto = proto;
        }
        
        public String sanitizeString(String value) {
            if (value == null) return null;
            
            String result = value;
            
            if (xss) {
                result = sanitizeXss(result);
            }
            if (sql) {
                result = sanitizeSql(result);
            }
            if (path) {
                result = sanitizePath(result);
            }
            
            return result;
        }
        
        public String sanitizeXss(String value) {
            if (value == null) return null;
            String result = value;
            result = XSS_SCRIPT.matcher(result).replaceAll("");
            result = XSS_JAVASCRIPT.matcher(result).replaceAll("");
            result = XSS_ON_EVENT.matcher(result).replaceAll(" ");
            result = XSS_DANGEROUS_TAGS.matcher(result).replaceAll("");
            result = result.replace("<", "&lt;")
                          .replace(">", "&gt;")
                          .replace("\"", "&quot;")
                          .replace("'", "&#x27;");
            return result;
        }
        
        public String sanitizeSql(String value) {
            if (value == null) return null;
            String result = value;
            result = SQL_KEYWORDS.matcher(result).replaceAll("");
            result = SQL_COMMENTS.matcher(result).replaceAll("");
            return result;
        }
        
        public String sanitizePath(String value) {
            if (value == null) return null;
            return PATH_TRAVERSAL.matcher(value).replaceAll("");
        }
        
        @SuppressWarnings("unchecked")
        public Map<String, Object> sanitizeObject(Map<String, Object> obj) {
            if (obj == null) return null;
            
            Map<String, Object> result = new LinkedHashMap<>();
            
            for (Map.Entry<String, Object> entry : obj.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                
                if (proto && PROTO_KEYS.contains(key)) continue;
                if (nosql && key.startsWith("$")) continue;
                
                if (value instanceof String) {
                    result.put(key, sanitizeString((String) value));
                } else if (value instanceof Map) {
                    result.put(key, sanitizeObject((Map<String, Object>) value));
                } else if (value instanceof List) {
                    result.put(key, sanitizeList((List<Object>) value));
                } else {
                    result.put(key, value);
                }
            }
            
            return result;
        }
        
        @SuppressWarnings("unchecked")
        private List<Object> sanitizeList(List<Object> list) {
            List<Object> result = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof String) {
                    result.add(sanitizeString((String) item));
                } else if (item instanceof Map) {
                    result.add(sanitizeObject((Map<String, Object>) item));
                } else if (item instanceof List) {
                    result.add(sanitizeList((List<Object>) item));
                } else {
                    result.add(item);
                }
            }
            return result;
        }
        
        public boolean isNoSqlKey(String key) {
            return NOSQL_OPERATORS.contains(key);
        }
        
        public boolean isProtoKey(String key) {
            return PROTO_KEYS.contains(key);
        }
    }
    
    // ========================================================================
    // RATE LIMITER
    // ========================================================================
    
    public static class RateLimiter {
        
        private final int max;
        private final long windowMs;
        private final String message;
        private final RateLimitStore store;
        private volatile boolean closed = false;
        
        public RateLimiter() {
            this(100, 60000, "Too many requests, please try again later.", new InMemoryStore());
        }
        
        public RateLimiter(int max, long windowMs, String message, RateLimitStore store) {
            this.max = max;
            this.windowMs = windowMs;
            this.message = message;
            this.store = store;
        }
        
        public RateLimitResult check(String key) {
            if (closed) {
                return new RateLimitResult(true, max, max, windowMs / 1000);
            }
            
            long now = System.currentTimeMillis();
            RateLimitEntry entry = store.get(key);
            
            if (entry == null || now - entry.windowStart >= windowMs) {
                entry = new RateLimitEntry(1, now);
                store.set(key, entry);
                return new RateLimitResult(true, max, max - 1, windowMs / 1000);
            }
            
            if (entry.count >= max) {
                long resetMs = windowMs - (now - entry.windowStart);
                return new RateLimitResult(false, max, 0, resetMs / 1000);
            }
            
            entry = new RateLimitEntry(entry.count + 1, entry.windowStart);
            store.set(key, entry);
            long resetMs = windowMs - (now - entry.windowStart);
            return new RateLimitResult(true, max, max - entry.count, resetMs / 1000);
        }
        
        public String getMessage() {
            return message;
        }
        
        public void close() {
            closed = true;
            store.close();
        }
        
        public static class RateLimitResult {
            public final boolean allowed;
            public final int limit;
            public final int remaining;
            public final long resetSeconds;
            
            public RateLimitResult(boolean allowed, int limit, int remaining, long resetSeconds) {
                this.allowed = allowed;
                this.limit = limit;
                this.remaining = remaining;
                this.resetSeconds = resetSeconds;
            }
        }
        
        public static class RateLimitEntry {
            public final int count;
            public final long windowStart;
            
            public RateLimitEntry(int count, long windowStart) {
                this.count = count;
                this.windowStart = windowStart;
            }
        }
        
        public interface RateLimitStore {
            RateLimitEntry get(String key);
            void set(String key, RateLimitEntry entry);
            void close();
        }
        
        public static class InMemoryStore implements RateLimitStore {
            private final ConcurrentHashMap<String, RateLimitEntry> entries = new ConcurrentHashMap<>();
            
            @Override
            public RateLimitEntry get(String key) {
                return entries.get(key);
            }
            
            @Override
            public void set(String key, RateLimitEntry entry) {
                entries.put(key, entry);
            }
            
            @Override
            public void close() {
                entries.clear();
            }
        }
    }
    
    // ========================================================================
    // SECURITY HEADERS
    // ========================================================================
    
    public static class SecurityHeaders {
        
        private String contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'";
        private boolean xssFilter = true;
        private boolean noSniff = true;
        private String frameOptions = "DENY";
        private String hsts = "max-age=31536000; includeSubDomains";
        private String referrerPolicy = "strict-origin-when-cross-origin";
        private String permissionsPolicy = "geolocation=(), microphone=(), camera=()";
        
        public SecurityHeaders() {}
        
        public Map<String, String> getHeaders() {
            Map<String, String> headers = new LinkedHashMap<>();
            
            if (contentSecurityPolicy != null) {
                headers.put("Content-Security-Policy", contentSecurityPolicy);
            }
            if (xssFilter) {
                headers.put("X-XSS-Protection", "1; mode=block");
            }
            if (noSniff) {
                headers.put("X-Content-Type-Options", "nosniff");
            }
            if (frameOptions != null) {
                headers.put("X-Frame-Options", frameOptions);
            }
            if (hsts != null) {
                headers.put("Strict-Transport-Security", hsts);
            }
            if (referrerPolicy != null) {
                headers.put("Referrer-Policy", referrerPolicy);
            }
            if (permissionsPolicy != null) {
                headers.put("Permissions-Policy", permissionsPolicy);
            }
            headers.put("X-Permitted-Cross-Domain-Policies", "none");
            
            return headers;
        }
        
        public Set<String> getHeadersToRemove() {
            return Set.of("X-Powered-By", "Server");
        }
        
        public SecurityHeaders setContentSecurityPolicy(String csp) {
            this.contentSecurityPolicy = csp;
            return this;
        }
        
        public SecurityHeaders setFrameOptions(String frameOptions) {
            this.frameOptions = frameOptions;
            return this;
        }
        
        public SecurityHeaders setHsts(String hsts) {
            this.hsts = hsts;
            return this;
        }
    }
    
    // ========================================================================
    // VALIDATOR
    // ========================================================================
    
    public static class Validator {
        
        private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
        );
        
        private static final Pattern URL_PATTERN = Pattern.compile(
            "^https?://[\\w.-]+(?:\\.[\\w.-]+)+[\\w.,@?^=%&:/~+#-]*$"
        );
        
        private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            Pattern.CASE_INSENSITIVE
        );
        
        public boolean isEmail(String value) {
            return value != null && EMAIL_PATTERN.matcher(value).matches();
        }
        
        public boolean isUrl(String value) {
            return value != null && URL_PATTERN.matcher(value).matches();
        }
        
        public boolean isUuid(String value) {
            return value != null && UUID_PATTERN.matcher(value).matches();
        }
        
        public ValidationResult validate(Map<String, Object> data, Map<String, FieldSchema> schema) {
            List<String> errors = new ArrayList<>();
            Map<String, Object> validated = new LinkedHashMap<>();
            
            for (Map.Entry<String, FieldSchema> entry : schema.entrySet()) {
                String field = entry.getKey();
                FieldSchema fieldSchema = entry.getValue();
                Object value = data.get(field);
                
                if (value == null) {
                    if (fieldSchema.required) {
                        errors.add(field + " is required");
                    }
                    continue;
                }
                
                String error = validateField(field, value, fieldSchema);
                if (error != null) {
                    errors.add(error);
                } else {
                    validated.put(field, value);
                }
            }
            
            return new ValidationResult(errors.isEmpty(), errors, validated);
        }
        
        private String validateField(String field, Object value, FieldSchema schema) {
            switch (schema.type) {
                case "string":
                    if (!(value instanceof String)) {
                        return field + " must be a string";
                    }
                    String strVal = (String) value;
                    if (schema.min != null && strVal.length() < schema.min) {
                        return field + " must be at least " + schema.min + " characters";
                    }
                    if (schema.max != null && strVal.length() > schema.max) {
                        return field + " must be at most " + schema.max + " characters";
                    }
                    if (schema.pattern != null && !schema.pattern.matcher(strVal).matches()) {
                        return field + " does not match required pattern";
                    }
                    break;
                    
                case "number":
                    if (!(value instanceof Number)) {
                        return field + " must be a number";
                    }
                    double numVal = ((Number) value).doubleValue();
                    if (schema.min != null && numVal < schema.min) {
                        return field + " must be at least " + schema.min;
                    }
                    if (schema.max != null && numVal > schema.max) {
                        return field + " must be at most " + schema.max;
                    }
                    break;
                    
                case "boolean":
                    if (!(value instanceof Boolean)) {
                        return field + " must be a boolean";
                    }
                    break;
                    
                case "email":
                    if (!(value instanceof String) || !isEmail((String) value)) {
                        return field + " must be a valid email";
                    }
                    break;
                    
                case "url":
                    if (!(value instanceof String) || !isUrl((String) value)) {
                        return field + " must be a valid URL";
                    }
                    break;
            }
            
            if (schema.enumValues != null && !schema.enumValues.contains(value)) {
                return field + " must be one of: " + schema.enumValues;
            }
            
            return null;
        }
        
        public static class FieldSchema {
            public String type = "string";
            public boolean required = false;
            public Integer min;
            public Integer max;
            public Pattern pattern;
            public Set<Object> enumValues;
            public boolean sanitize = true;
            
            public FieldSchema type(String type) { this.type = type; return this; }
            public FieldSchema required() { this.required = true; return this; }
            public FieldSchema min(int min) { this.min = min; return this; }
            public FieldSchema max(int max) { this.max = max; return this; }
            public FieldSchema pattern(String pattern) { this.pattern = Pattern.compile(pattern); return this; }
            public FieldSchema enumValues(Object... values) { this.enumValues = Set.of(values); return this; }
        }
        
        public static class ValidationResult {
            public final boolean valid;
            public final List<String> errors;
            public final Map<String, Object> data;
            
            public ValidationResult(boolean valid, List<String> errors, Map<String, Object> data) {
                this.valid = valid;
                this.errors = errors;
                this.data = data;
            }
        }
    }
    
    // ========================================================================
    // SAFE LOGGER
    // ========================================================================
    
    public static class SafeLogger {
        
        private static final Set<String> DEFAULT_REDACT_KEYS = Set.of(
            "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
            "auth", "authorization", "bearer", "credential", "private", "ssn",
            "creditcard", "credit_card", "cardnumber", "card_number", "cvv"
        );
        
        private final Set<String> redactKeys;
        private final int maxLength;
        
        public SafeLogger() {
            this(DEFAULT_REDACT_KEYS, 10000);
        }
        
        public SafeLogger(Set<String> redactKeys, int maxLength) {
            this.redactKeys = redactKeys;
            this.maxLength = maxLength;
        }
        
        public void info(String message) {
            log("INFO", message, null);
        }
        
        public void info(String message, Map<String, Object> data) {
            log("INFO", message, data);
        }
        
        public void warn(String message) {
            log("WARN", message, null);
        }
        
        public void warn(String message, Map<String, Object> data) {
            log("WARN", message, data);
        }
        
        public void error(String message) {
            log("ERROR", message, null);
        }
        
        public void error(String message, Map<String, Object> data) {
            log("ERROR", message, data);
        }
        
        public void log(String level, String message, Map<String, Object> data) {
            String safeMessage = sanitizeLogMessage(message);
            Map<String, Object> safeData = data != null ? redactSensitive(data) : null;
            
            StringBuilder sb = new StringBuilder();
            sb.append("{\"level\":\"").append(level).append("\"");
            sb.append(",\"message\":\"").append(escapeJson(safeMessage)).append("\"");
            sb.append(",\"timestamp\":\"").append(java.time.Instant.now()).append("\"");
            
            if (safeData != null) {
                sb.append(",\"data\":").append(toJson(safeData));
            }
            sb.append("}");
            
            System.out.println(sb);
        }
        
        private String sanitizeLogMessage(String message) {
            if (message == null) return "";
            String clean = message.replaceAll("[\\n\\r\\t]", " ");
            if (clean.length() > maxLength) {
                clean = clean.substring(0, maxLength) + "...[truncated]";
            }
            return clean;
        }
        
        @SuppressWarnings("unchecked")
        private Map<String, Object> redactSensitive(Map<String, Object> data) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : data.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                
                if (shouldRedact(key)) {
                    result.put(key, "[REDACTED]");
                } else if (value instanceof Map) {
                    result.put(key, redactSensitive((Map<String, Object>) value));
                } else if (value instanceof String) {
                    String strVal = (String) value;
                    if (strVal.length() > maxLength) {
                        result.put(key, strVal.substring(0, maxLength) + "...[truncated]");
                    } else {
                        result.put(key, value);
                    }
                } else {
                    result.put(key, value);
                }
            }
            return result;
        }
        
        private boolean shouldRedact(String key) {
            String lower = key.toLowerCase();
            return redactKeys.stream().anyMatch(lower::contains);
        }
        
        private String escapeJson(String s) {
            return s.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
        }
        
        private String toJson(Map<String, Object> data) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> entry : data.entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(escapeJson(entry.getKey())).append("\":");
                Object val = entry.getValue();
                if (val instanceof String) {
                    sb.append("\"").append(escapeJson((String) val)).append("\"");
                } else if (val instanceof Map) {
                    sb.append(toJson((Map<String, Object>) val));
                } else if (val == null) {
                    sb.append("null");
                } else {
                    sb.append(val);
                }
                first = false;
            }
            return sb.append("}").toString();
        }
    }
    
    // ========================================================================
    // ERROR HANDLER
    // ========================================================================
    
    public static class ErrorHandler {
        
        private final boolean isDev;
        
        public ErrorHandler(boolean isDev) {
            this.isDev = isDev;
        }
        
        public Map<String, Object> handle(Throwable error) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("error", true);
            
            if (isDev) {
                response.put("message", error.getMessage());
                response.put("stack", getStackTraceString(error));
            } else {
                response.put("message", "An unexpected error occurred");
            }
            
            return response;
        }
        
        private String getStackTraceString(Throwable error) {
            java.io.StringWriter sw = new java.io.StringWriter();
            error.printStackTrace(new java.io.PrintWriter(sw));
            return sw.toString();
        }
    }
    
    // ========================================================================
    // EXCEPTIONS
    // ========================================================================
    
    public static class RateLimitExceededException extends RuntimeException {
        public RateLimitExceededException(String message) {
            super(message);
        }
    }
    
    public static class ValidationException extends RuntimeException {
        private final List<String> errors;
        
        public ValidationException(List<String> errors) {
            super("Validation failed: " + String.join(", ", errors));
            this.errors = errors;
        }
        
        public List<String> getErrors() {
            return errors;
        }
    }
    
    public static class InputTooLargeException extends RuntimeException {
        public InputTooLargeException(String message) {
            super(message);
        }
    }
}
