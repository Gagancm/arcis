using Xunit;
using Shield;

namespace Shield.Tests;

/// <summary>
/// Shield C# Test Suite
/// 
/// Tests aligned with TEST_VECTORS.json spec for cross-platform consistency.
/// Run with: dotnet test
/// </summary>
public class ShieldTests : IDisposable
{
    private readonly ShieldInstance _shield;

    public ShieldTests()
    {
        _shield = ShieldBuilder.Create().Build();
    }

    public void Dispose()
    {
        _shield.Dispose();
    }

    // ========================================================================
    // SANITIZE STRING - XSS TESTS
    // ========================================================================

    [Fact]
    public void SanitizeXss_ScriptTag_RemovesScript()
    {
        var input = "<script>alert('xss')</script>";
        var result = _shield.Sanitizer.SanitizeString(input);
        
        Assert.DoesNotContain("<script", result);
        Assert.DoesNotContain("</script>", result);
    }

    [Fact]
    public void SanitizeXss_JavascriptProtocol_RemovesJavascript()
    {
        var input = "javascript:alert('xss')";
        var result = _shield.Sanitizer.SanitizeString(input);
        
        Assert.DoesNotContain("javascript:", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SanitizeXss_OnEventHandler_RemovesEvent()
    {
        var input = "<img onerror=\"alert('xss')\" src=x>";
        var result = _shield.Sanitizer.SanitizeString(input);
        
        Assert.DoesNotContain("onerror", result);
    }

    [Fact]
    public void SanitizeXss_HtmlEntities_EncodesEntities()
    {
        var input = "<div>test</div>";
        var result = _shield.Sanitizer.SanitizeXss(input);
        
        Assert.True(result.Contains("&lt;") || !result.Contains("<div>"));
    }

    // ========================================================================
    // SANITIZE STRING - SQL INJECTION TESTS
    // ========================================================================

    [Fact]
    public void SanitizeSql_SelectStatement_RemovesSelect()
    {
        var input = "SELECT * FROM users";
        var result = _shield.Sanitizer.SanitizeString(input);
        
        Assert.DoesNotContain("SELECT", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SanitizeSql_UnionStatement_RemovesUnion()
    {
        var input = "1 UNION SELECT password FROM users";
        var result = _shield.Sanitizer.SanitizeString(input);
        
        Assert.DoesNotContain("UNION", result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SELECT", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SanitizeSql_Comment_RemovesComment()
    {
        var input = "admin'--";
        var result = _shield.Sanitizer.SanitizeSql(input);
        
        Assert.DoesNotContain("--", result);
    }

    // ========================================================================
    // SANITIZE STRING - PATH TRAVERSAL TESTS
    // ========================================================================

    [Fact]
    public void SanitizePath_Traversal_RemovesTraversal()
    {
        var input = "../../../etc/passwd";
        var result = _shield.Sanitizer.SanitizeString(input);
        
        Assert.DoesNotContain("../", result);
    }

    [Fact]
    public void SanitizePath_EncodedTraversal_RemovesEncoded()
    {
        var input = "%2e%2e%2f%2e%2e%2fetc/passwd";
        var result = _shield.Sanitizer.SanitizeString(input);
        
        Assert.DoesNotContain("%2e%2e", result, StringComparison.OrdinalIgnoreCase);
    }

    // ========================================================================
    // SANITIZE OBJECT TESTS
    // ========================================================================

    [Fact]
    public void SanitizeObject_ProtoKeys_BlocksProto()
    {
        var input = new Dictionary<string, object?>
        {
            ["name"] = "test",
            ["__proto__"] = new Dictionary<string, object?> { ["admin"] = true }
        };

        var result = _shield.Sanitizer.SanitizeObject(input);

        Assert.True(result.ContainsKey("name"));
        Assert.False(result.ContainsKey("__proto__"));
    }

    [Fact]
    public void SanitizeObject_NoSqlOperators_BlocksOperators()
    {
        var input = new Dictionary<string, object?>
        {
            ["name"] = "test",
            ["$gt"] = 0
        };

        var result = _shield.Sanitizer.SanitizeObject(input);

        Assert.True(result.ContainsKey("name"));
        Assert.False(result.ContainsKey("$gt"));
    }

    [Fact]
    public void SanitizeObject_NestedStrings_SanitizesNested()
    {
        var input = new Dictionary<string, object?>
        {
            ["user"] = new Dictionary<string, object?>
            {
                ["bio"] = "<script>alert('xss')</script>"
            }
        };

        var result = _shield.Sanitizer.SanitizeObject(input);

        var user = result["user"] as Dictionary<string, object?>;
        var bio = user?["bio"] as string;
        Assert.DoesNotContain("<script", bio);
    }

    // ========================================================================
    // RATE LIMITER TESTS
    // ========================================================================

    [Fact]
    public void RateLimiter_WithinLimit_Allows()
    {
        var options = new RateLimitOptions { Max = 5, Window = TimeSpan.FromMinutes(1) };
        using var limiter = new RateLimiter(options, new InMemoryRateLimitStore());

        for (int i = 0; i < 5; i++)
        {
            var result = limiter.Check("test-ip");
            Assert.True(result.Allowed);
        }
    }

    [Fact]
    public void RateLimiter_OverLimit_Blocks()
    {
        var options = new RateLimitOptions { Max = 3, Window = TimeSpan.FromMinutes(1) };
        using var limiter = new RateLimiter(options, new InMemoryRateLimitStore());

        for (int i = 0; i < 3; i++)
        {
            limiter.Check("test-ip");
        }

        var result = limiter.Check("test-ip");
        Assert.False(result.Allowed);
        Assert.Equal(0, result.Remaining);
    }

    [Fact]
    public void RateLimiter_DifferentKeys_TracksIndependently()
    {
        var options = new RateLimitOptions { Max = 2, Window = TimeSpan.FromMinutes(1) };
        using var limiter = new RateLimiter(options, new InMemoryRateLimitStore());

        limiter.Check("ip-1");
        limiter.Check("ip-1");
        var blocked = limiter.Check("ip-1");

        var allowed = limiter.Check("ip-2");

        Assert.False(blocked.Allowed);
        Assert.True(allowed.Allowed);
    }

    // ========================================================================
    // SECURITY HEADERS TESTS
    // ========================================================================

    [Fact]
    public void SecurityHeaders_Defaults_HasAllHeaders()
    {
        var headers = _shield.Headers.GetHeaders();

        Assert.True(headers.ContainsKey("Content-Security-Policy"));
        Assert.True(headers.ContainsKey("X-XSS-Protection"));
        Assert.True(headers.ContainsKey("X-Content-Type-Options"));
        Assert.True(headers.ContainsKey("X-Frame-Options"));
        Assert.True(headers.ContainsKey("Strict-Transport-Security"));

        Assert.Equal("nosniff", headers["X-Content-Type-Options"]);
        Assert.Equal("DENY", headers["X-Frame-Options"]);
    }

    [Fact]
    public void SecurityHeaders_ToRemove_IncludesPoweredBy()
    {
        var toRemove = _shield.Headers.HeadersToRemove;

        Assert.Contains("X-Powered-By", toRemove);
    }

    // ========================================================================
    // VALIDATOR TESTS
    // ========================================================================

    [Fact]
    public void Validator_Email_Valid()
    {
        Assert.True(_shield.Validator.IsEmail("test@example.com"));
        Assert.False(_shield.Validator.IsEmail("not-an-email"));
        Assert.False(_shield.Validator.IsEmail("@example.com"));
    }

    [Fact]
    public void Validator_Url_Valid()
    {
        Assert.True(_shield.Validator.IsUrl("https://example.com"));
        Assert.True(_shield.Validator.IsUrl("http://example.com/path"));
        Assert.False(_shield.Validator.IsUrl("not-a-url"));
        Assert.False(_shield.Validator.IsUrl("ftp://example.com"));
    }

    [Fact]
    public void Validator_Uuid_Valid()
    {
        Assert.True(_shield.Validator.IsUuid("550e8400-e29b-41d4-a716-446655440000"));
        Assert.False(_shield.Validator.IsUuid("not-a-uuid"));
        Assert.False(_shield.Validator.IsUuid("550e8400-e29b-41d4-a716"));
    }

    [Fact]
    public void Validator_Schema_Required()
    {
        var data = new Dictionary<string, object?>
        {
            ["name"] = "test"
        };

        var schema = new Dictionary<string, FieldSchema>
        {
            ["name"] = new FieldSchema { Type = "string", Required = true },
            ["email"] = new FieldSchema { Type = "email", Required = true }
        };

        var result = _shield.Validator.Validate(data, schema);

        Assert.False(result.Valid);
        Assert.Contains(result.Errors, e => e.Contains("email"));
    }

    // ========================================================================
    // SAFE LOGGER TESTS
    // ========================================================================

    [Fact]
    public void SafeLogger_RedactsSensitiveKeys_DoesNotThrow()
    {
        var exception = Record.Exception(() =>
        {
            _shield.Logger.Info("Test message", new Dictionary<string, object?>
            {
                ["username"] = "john",
                ["password"] = "secret123"
            });
        });

        Assert.Null(exception);
    }

    // ========================================================================
    // ERROR HANDLER TESTS
    // ========================================================================

    [Fact]
    public void ErrorHandler_ProductionMode_HidesDetails()
    {
        var handler = new ErrorHandler(false);
        var result = handler.Handle(new Exception("Sensitive error"));

        Assert.Equal("An unexpected error occurred", result["message"]);
        Assert.False(result.ContainsKey("stack"));
    }

    [Fact]
    public void ErrorHandler_DevMode_ShowsDetails()
    {
        var handler = new ErrorHandler(true);
        var result = handler.Handle(new Exception("Test error"));

        Assert.Equal("Test error", result["message"]);
        Assert.True(result.ContainsKey("stack"));
    }
}
