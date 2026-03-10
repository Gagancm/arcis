using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Arcis;

/// <summary>
/// Arcis Security Library for .NET
///
/// One-line security for ASP.NET Core applications providing:
/// - Input sanitization (XSS, SQL, NoSQL, Path traversal)
/// - Rate limiting with configurable windows
/// - Security headers
/// - Request validation
/// - Safe logging with redaction
/// - Production-safe error handling
///
/// Usage with ASP.NET Core:
/// <code>
/// // In Program.cs
/// builder.Services.AddArcis();
///
/// // In middleware pipeline
/// app.UseArcis();
///
/// // Or with options
/// app.UseArcis(options => {
///     options.RateLimitMax = 50;
///     options.EnableXssSanitization = true;
/// });
/// </code>
///
/// Standalone usage:
/// <code>
/// var arcis = ArcisBuilder.Create().Build();
/// var clean = arcis.Sanitizer.SanitizeString(userInput);
/// </code>
/// </summary>
public class ArcisInstance : IDisposable
{
    public Sanitizer Sanitizer { get; }
    public RateLimiter RateLimiter { get; }
    public SecurityHeaders Headers { get; }
    public Validator Validator { get; }
    public SafeLogger Logger { get; }
    public ErrorHandler ErrorHandler { get; }

    internal ArcisInstance(
        Sanitizer sanitizer,
        RateLimiter rateLimiter,
        SecurityHeaders headers,
        Validator validator,
        SafeLogger logger,
        ErrorHandler errorHandler)
    {
        Sanitizer = sanitizer;
        RateLimiter = rateLimiter;
        Headers = headers;
        Validator = validator;
        Logger = logger;
        ErrorHandler = errorHandler;
    }

    public void Dispose()
    {
        RateLimiter.Dispose();
        GC.SuppressFinalize(this);
    }
}

public class ArcisBuilder
{
    private Sanitizer? _sanitizer;
    private RateLimiter? _rateLimiter;
    private SecurityHeaders? _headers;
    private Validator? _validator;
    private SafeLogger? _logger;
    private ErrorHandler? _errorHandler;

    public static ArcisBuilder Create() => new();

    public ArcisBuilder WithSanitizer(Sanitizer sanitizer)
    {
        _sanitizer = sanitizer;
        return this;
    }

    public ArcisBuilder WithRateLimiter(RateLimiter limiter)
    {
        _rateLimiter = limiter;
        return this;
    }

    public ArcisBuilder WithHeaders(SecurityHeaders headers)
    {
        _headers = headers;
        return this;
    }

    public ArcisBuilder WithValidator(Validator validator)
    {
        _validator = validator;
        return this;
    }

    public ArcisBuilder WithLogger(SafeLogger logger)
    {
        _logger = logger;
        return this;
    }

    public ArcisBuilder WithErrorHandler(ErrorHandler handler)
    {
        _errorHandler = handler;
        return this;
    }

    public ArcisInstance Build()
    {
        return new ArcisInstance(
            _sanitizer ?? new Sanitizer(),
            _rateLimiter ?? new RateLimiter(),
            _headers ?? new SecurityHeaders(),
            _validator ?? new Validator(),
            _logger ?? new SafeLogger(),
            _errorHandler ?? new ErrorHandler(false)
        );
    }
}

// ============================================================================
// SANITIZER
// ============================================================================

public class SanitizeOptions
{
    public bool Xss { get; set; } = true;
    public bool Sql { get; set; } = true;
    public bool NoSql { get; set; } = true;
    public bool Path { get; set; } = true;
    public bool Proto { get; set; } = true;
}

public class Sanitizer
{
    private static readonly Regex XssScript = new(
        @"<script[^>]*>.*?</script>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex XssJavascript = new(
        @"javascript:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex XssOnEvent = new(
        @"\s+on\w+\s*=",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex XssDangerousTags = new(
        @"<(iframe|object|embed|form|input)[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SqlKeywords = new(
        @"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex SqlComments = new(
        @"(--|/\*|\*/|;\s*$)",
        RegexOptions.Compiled);

    private static readonly Regex PathTraversal = new(
        @"(\.\./|\.\.\\|%2e%2e|%252e)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly HashSet<string> NoSqlOperators = new(StringComparer.OrdinalIgnoreCase)
    {
        "$gt", "$gte", "$lt", "$lte", "$ne", "$eq",
        "$in", "$nin", "$and", "$or", "$not",
        "$exists", "$type", "$regex", "$where", "$expr"
    };

    private static readonly HashSet<string> ProtoKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "__proto__", "constructor", "prototype"
    };

    private readonly SanitizeOptions _options;

    public Sanitizer() : this(new SanitizeOptions()) { }

    public Sanitizer(SanitizeOptions options)
    {
        _options = options;
    }

    public string? SanitizeString(string? value)
    {
        if (value == null) return null;

        var result = value;

        if (_options.Xss) result = SanitizeXss(result);
        if (_options.Sql) result = SanitizeSql(result);
        if (_options.Path) result = SanitizePath(result);

        return result;
    }

    public string SanitizeXss(string value)
    {
        var result = XssScript.Replace(value, "");
        result = XssJavascript.Replace(result, "");
        result = XssOnEvent.Replace(result, " ");
        result = XssDangerousTags.Replace(result, "");
        result = result
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#x27;");
        return result;
    }

    public string SanitizeSql(string value)
    {
        var result = SqlKeywords.Replace(value, "");
        result = SqlComments.Replace(result, "");
        return result;
    }

    public string SanitizePath(string value)
    {
        return PathTraversal.Replace(value, "");
    }

    public Dictionary<string, object?> SanitizeObject(Dictionary<string, object?> obj)
    {
        var result = new Dictionary<string, object?>();

        foreach (var (key, value) in obj)
        {
            if (_options.Proto && ProtoKeys.Contains(key)) continue;
            if (_options.NoSql && key.StartsWith("$")) continue;

            result[key] = value switch
            {
                string s => SanitizeString(s),
                Dictionary<string, object?> d => SanitizeObject(d),
                List<object?> l => SanitizeList(l),
                _ => value
            };
        }

        return result;
    }

    private List<object?> SanitizeList(List<object?> list)
    {
        var result = new List<object?>();

        foreach (var item in list)
        {
            result.Add(item switch
            {
                string s => SanitizeString(s),
                Dictionary<string, object?> d => SanitizeObject(d),
                List<object?> l => SanitizeList(l),
                _ => item
            });
        }

        return result;
    }

    public bool IsNoSqlKey(string key) => NoSqlOperators.Contains(key);
    public bool IsProtoKey(string key) => ProtoKeys.Contains(key);
}

// ============================================================================
// RATE LIMITER
// ============================================================================

public class RateLimitOptions
{
    public int Max { get; set; } = 100;
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
    public string Message { get; set; } = "Too many requests, please try again later.";
}

public record RateLimitEntry(int Count, DateTime WindowStart);

public record RateLimitResult(bool Allowed, int Limit, int Remaining, TimeSpan ResetIn);

public interface IRateLimitStore : IDisposable
{
    RateLimitEntry? Get(string key);
    void Set(string key, RateLimitEntry entry);
}

public class InMemoryRateLimitStore : IRateLimitStore
{
    private readonly ConcurrentDictionary<string, RateLimitEntry> _entries = new();

    public RateLimitEntry? Get(string key) =>
        _entries.TryGetValue(key, out var entry) ? entry : null;

    public void Set(string key, RateLimitEntry entry) =>
        _entries[key] = entry;

    public void Dispose() => _entries.Clear();
}

public class RateLimiter : IDisposable
{
    private readonly RateLimitOptions _options;
    private readonly IRateLimitStore _store;
    private bool _disposed;

    public RateLimiter() : this(new RateLimitOptions(), new InMemoryRateLimitStore()) { }

    public RateLimiter(RateLimitOptions options, IRateLimitStore store)
    {
        _options = options;
        _store = store;
    }

    public RateLimitResult Check(string key)
    {
        if (_disposed)
            return new RateLimitResult(true, _options.Max, _options.Max, _options.Window);

        var now = DateTime.UtcNow;
        var entry = _store.Get(key);

        if (entry == null || now - entry.WindowStart >= _options.Window)
        {
            entry = new RateLimitEntry(1, now);
            _store.Set(key, entry);
            return new RateLimitResult(true, _options.Max, _options.Max - 1, _options.Window);
        }

        if (entry.Count >= _options.Max)
        {
            var resetIn = _options.Window - (now - entry.WindowStart);
            return new RateLimitResult(false, _options.Max, 0, resetIn);
        }

        entry = entry with { Count = entry.Count + 1 };
        _store.Set(key, entry);
        var remaining = _options.Max - entry.Count;
        var resetTime = _options.Window - (now - entry.WindowStart);
        return new RateLimitResult(true, _options.Max, remaining, resetTime);
    }

    public string Message => _options.Message;

    public void Dispose()
    {
        _disposed = true;
        _store.Dispose();
        GC.SuppressFinalize(this);
    }
}

// ============================================================================
// SECURITY HEADERS
// ============================================================================

public class SecurityHeaderOptions
{
    public string ContentSecurityPolicy { get; set; } =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'";

    public bool XssFilter { get; set; } = true;
    public bool NoSniff { get; set; } = true;
    public string FrameOptions { get; set; } = "DENY";
    public string Hsts { get; set; } = "max-age=31536000; includeSubDomains";
    public string ReferrerPolicy { get; set; } = "strict-origin-when-cross-origin";
    public string PermissionsPolicy { get; set; } = "geolocation=(), microphone=(), camera=()";
}

public class SecurityHeaders
{
    private readonly SecurityHeaderOptions _options;

    public SecurityHeaders() : this(new SecurityHeaderOptions()) { }

    public SecurityHeaders(SecurityHeaderOptions options)
    {
        _options = options;
    }

    public Dictionary<string, string> GetHeaders()
    {
        var headers = new Dictionary<string, string>();

        if (!string.IsNullOrEmpty(_options.ContentSecurityPolicy))
            headers["Content-Security-Policy"] = _options.ContentSecurityPolicy;

        if (_options.XssFilter)
            headers["X-XSS-Protection"] = "1; mode=block";

        if (_options.NoSniff)
            headers["X-Content-Type-Options"] = "nosniff";

        if (!string.IsNullOrEmpty(_options.FrameOptions))
            headers["X-Frame-Options"] = _options.FrameOptions;

        if (!string.IsNullOrEmpty(_options.Hsts))
            headers["Strict-Transport-Security"] = _options.Hsts;

        if (!string.IsNullOrEmpty(_options.ReferrerPolicy))
            headers["Referrer-Policy"] = _options.ReferrerPolicy;

        if (!string.IsNullOrEmpty(_options.PermissionsPolicy))
            headers["Permissions-Policy"] = _options.PermissionsPolicy;

        headers["X-Permitted-Cross-Domain-Policies"] = "none";

        return headers;
    }

    public HashSet<string> HeadersToRemove => new() { "X-Powered-By", "Server" };
}

// ============================================================================
// VALIDATOR
// ============================================================================

public class FieldSchema
{
    public string Type { get; set; } = "string";
    public bool Required { get; set; }
    public int? Min { get; set; }
    public int? Max { get; set; }
    public Regex? Pattern { get; set; }
    public HashSet<object>? EnumValues { get; set; }
    public bool Sanitize { get; set; } = true;
}

public record ValidationResult(bool Valid, List<string> Errors, Dictionary<string, object?> Data);

public class Validator
{
    private static readonly Regex EmailPattern = new(
        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled);

    private static readonly Regex UrlPattern = new(
        @"^https?://[\w.-]+(?:\.[\w.-]+)+[\w.,@?^=%&:/~+#-]*$",
        RegexOptions.Compiled);

    private static readonly Regex UuidPattern = new(
        @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public bool IsEmail(string? value) => value != null && EmailPattern.IsMatch(value);
    public bool IsUrl(string? value) => value != null && UrlPattern.IsMatch(value);
    public bool IsUuid(string? value) => value != null && UuidPattern.IsMatch(value);

    public ValidationResult Validate(
        Dictionary<string, object?> data,
        Dictionary<string, FieldSchema> schema)
    {
        var errors = new List<string>();
        var validated = new Dictionary<string, object?>();

        foreach (var (field, fieldSchema) in schema)
        {
            data.TryGetValue(field, out var value);

            if (value == null)
            {
                if (fieldSchema.Required)
                    errors.Add($"{field} is required");
                continue;
            }

            var error = ValidateField(field, value, fieldSchema);
            if (error != null)
                errors.Add(error);
            else
                validated[field] = value;
        }

        return new ValidationResult(errors.Count == 0, errors, validated);
    }

    private string? ValidateField(string field, object value, FieldSchema schema)
    {
        switch (schema.Type)
        {
            case "string":
                if (value is not string strVal)
                    return $"{field} must be a string";
                if (schema.Min.HasValue && strVal.Length < schema.Min)
                    return $"{field} must be at least {schema.Min} characters";
                if (schema.Max.HasValue && strVal.Length > schema.Max)
                    return $"{field} must be at most {schema.Max} characters";
                if (schema.Pattern != null && !schema.Pattern.IsMatch(strVal))
                    return $"{field} does not match required pattern";
                break;

            case "number":
                if (value is not (int or long or float or double or decimal))
                    return $"{field} must be a number";
                var numVal = Convert.ToDouble(value);
                if (schema.Min.HasValue && numVal < schema.Min)
                    return $"{field} must be at least {schema.Min}";
                if (schema.Max.HasValue && numVal > schema.Max)
                    return $"{field} must be at most {schema.Max}";
                break;

            case "boolean":
                if (value is not bool)
                    return $"{field} must be a boolean";
                break;

            case "email":
                if (value is not string emailVal || !IsEmail(emailVal))
                    return $"{field} must be a valid email";
                break;

            case "url":
                if (value is not string urlVal || !IsUrl(urlVal))
                    return $"{field} must be a valid URL";
                break;
        }

        if (schema.EnumValues != null && !schema.EnumValues.Contains(value))
            return $"{field} must be one of: {string.Join(", ", schema.EnumValues)}";

        return null;
    }
}

// ============================================================================
// SAFE LOGGER
// ============================================================================

public class SafeLoggerOptions
{
    public HashSet<string> RedactKeys { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "auth", "authorization", "bearer", "credential", "private", "ssn",
        "creditcard", "credit_card", "cardnumber", "card_number", "cvv"
    };

    public int MaxLength { get; set; } = 10000;
}

public class SafeLogger
{
    private readonly SafeLoggerOptions _options;

    public SafeLogger() : this(new SafeLoggerOptions()) { }

    public SafeLogger(SafeLoggerOptions options)
    {
        _options = options;
    }

    public void Info(string message, Dictionary<string, object?>? data = null) =>
        Log("INFO", message, data);

    public void Warn(string message, Dictionary<string, object?>? data = null) =>
        Log("WARN", message, data);

    public void Error(string message, Dictionary<string, object?>? data = null) =>
        Log("ERROR", message, data);

    public void Log(string level, string message, Dictionary<string, object?>? data = null)
    {
        var safeMessage = SanitizeLogMessage(message);
        var safeData = data != null ? RedactSensitive(data) : null;

        var logEntry = new Dictionary<string, object?>
        {
            ["level"] = level,
            ["message"] = safeMessage,
            ["timestamp"] = DateTime.UtcNow.ToString("O")
        };

        if (safeData != null)
            logEntry["data"] = safeData;

        Console.WriteLine(JsonSerializer.Serialize(logEntry));
    }

    private string SanitizeLogMessage(string message)
    {
        var clean = Regex.Replace(message, @"[\n\r\t]", " ");
        if (clean.Length > _options.MaxLength)
            clean = clean[.._options.MaxLength] + "...[truncated]";
        return clean;
    }

    private Dictionary<string, object?> RedactSensitive(Dictionary<string, object?> data)
    {
        var result = new Dictionary<string, object?>();

        foreach (var (key, value) in data)
        {
            if (ShouldRedact(key))
            {
                result[key] = "[REDACTED]";
            }
            else if (value is Dictionary<string, object?> nested)
            {
                result[key] = RedactSensitive(nested);
            }
            else if (value is string strVal && strVal.Length > _options.MaxLength)
            {
                result[key] = strVal[.._options.MaxLength] + "...[truncated]";
            }
            else
            {
                result[key] = value;
            }
        }

        return result;
    }

    private bool ShouldRedact(string key) =>
        _options.RedactKeys.Any(k => key.Contains(k, StringComparison.OrdinalIgnoreCase));
}

// ============================================================================
// ERROR HANDLER
// ============================================================================

public class ErrorHandler
{
    private readonly bool _isDev;

    public ErrorHandler(bool isDev)
    {
        _isDev = isDev;
    }

    public Dictionary<string, object?> Handle(Exception error)
    {
        var response = new Dictionary<string, object?>
        {
            ["error"] = true
        };

        if (_isDev)
        {
            response["message"] = error.Message;
            response["stack"] = error.StackTrace;
        }
        else
        {
            response["message"] = "An unexpected error occurred";
        }

        return response;
    }
}

// ============================================================================
// EXCEPTIONS
// ============================================================================

public class RateLimitExceededException : Exception
{
    public RateLimitExceededException(string message) : base(message) { }
}

public class ValidationException : Exception
{
    public List<string> Errors { get; }

    public ValidationException(List<string> errors)
        : base($"Validation failed: {string.Join(", ", errors)}")
    {
        Errors = errors;
    }
}

public class InputTooLargeException : Exception
{
    public InputTooLargeException(string message) : base(message) { }
}
