/*
Package echo provides Shield middleware adapters for the Echo web framework.

Usage:

	import (
		"github.com/labstack/echo/v4"
		shieldecho "github.com/aspect.dev/shield-go/echo"
	)

	func main() {
		e := echo.New()

		// Full protection with defaults
		e.Use(shieldecho.Middleware())

		// Or with custom config
		e.Use(shieldecho.MiddlewareWithConfig(shieldecho.Config{
			RateLimitMax:    50,
			RateLimitWindow: time.Minute,
			CSP:             "default-src 'self'",
		}))

		// Granular middleware
		e.Use(shieldecho.Headers())
		e.Use(shieldecho.RateLimit(100, time.Minute))
		e.Use(shieldecho.Sanitizer())

		e.GET("/", handler)
		e.Start(":8080")
	}

# Resource Cleanup

Shield's rate limiter runs a background goroutine for cleanup. Call Cleanup()
when your application shuts down to stop this goroutine and release resources:

	import (
		"context"
		"os/signal"
		"syscall"
		shieldecho "github.com/aspect.dev/shield-go/echo"
	)

	func main() {
		e := echo.New()
		e.Use(shieldecho.Middleware())

		// Graceful shutdown
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go e.Start(":8080")

		<-ctx.Done()
		e.Shutdown(context.Background())
		shieldecho.Cleanup() // Stop rate limiter background goroutines
	}

Alternatively, register cleanup with a defer or shutdown hook:

	func main() {
		defer shieldecho.Cleanup()
		// ... rest of setup
	}
*/
package echo

import (
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	shield "github.com/aspect.dev/shield-go"
)

// Config holds Shield middleware configuration for Echo.
type Config struct {
	// Sanitizer options
	Sanitize      bool
	SanitizeXSS   bool
	SanitizeSQL   bool
	SanitizeNoSQL bool
	SanitizePath  bool
	SanitizeCmd   bool
	MaxInputSize  int

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(echo.Context) bool

	// Security headers options
	Headers           bool
	CSP               string
	FrameOptions      string
	HSTSMaxAge        int
	HSTSSubdomains    bool
	ReferrerPolicy    string
	PermissionsPolicy string
	CacheControl      bool

	// Error handler options
	IsDev bool
}

// DefaultConfig returns the default Shield configuration for Echo.
func DefaultConfig() Config {
	return Config{
		Sanitize:          true,
		SanitizeXSS:       true,
		SanitizeSQL:       true,
		SanitizeNoSQL:     true,
		SanitizePath:      true,
		SanitizeCmd:       true,
		MaxInputSize:      1000000,
		RateLimit:         true,
		RateLimitMax:      100,
		RateLimitWindow:   time.Minute,
		Headers:           true,
		CSP:               "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
		FrameOptions:      "DENY",
		HSTSMaxAge:        31536000,
		HSTSSubdomains:    true,
		ReferrerPolicy:    "strict-origin-when-cross-origin",
		PermissionsPolicy: "geolocation=(), microphone=(), camera=()",
		CacheControl:      true,
		IsDev:             false,
	}
}

// Context key for Shield components
const (
	SanitizerKey     = "shield_sanitizer"
	ValidatedBodyKey = "shield_validated_body"
)

// shieldInstance holds the Shield components for cleanup.
type shieldInstance struct {
	rateLimiter *shield.RateLimiter
}

// Close cleans up Shield resources, stopping the rate limiter's
// background cleanup goroutine.
func (s *shieldInstance) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

// activeInstances tracks Shield instances for cleanup.
var activeInstances []*shieldInstance

// Cleanup closes all active Shield middleware instances and releases resources.
// This stops the background goroutines used by rate limiters for automatic
// cleanup of expired entries.
//
// Call Cleanup() when your application shuts down to prevent goroutine leaks.
// This is especially important in long-running applications or when using
// hot-reloading during development.
//
// Example:
//
//	func main() {
//		defer shieldecho.Cleanup()
//		e := echo.New()
//		e.Use(shieldecho.Middleware())
//		e.Start(":8080")
//	}
//
// For graceful shutdown with signal handling:
//
//	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
//	defer stop()
//	go e.Start(":8080")
//	<-ctx.Done()
//	e.Shutdown(context.Background())
//	shieldecho.Cleanup()
func Cleanup() {
	for _, instance := range activeInstances {
		instance.Close()
	}
	activeInstances = nil
}

// Middleware returns an Echo middleware with default Shield configuration.
func Middleware() echo.MiddlewareFunc {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns an Echo middleware with custom configuration.
func MiddlewareWithConfig(config Config) echo.MiddlewareFunc {
	// Convert to core Shield config
	shieldConfig := shield.Config{
		Sanitize:          config.Sanitize,
		SanitizeXSS:       config.SanitizeXSS,
		SanitizeSQL:       config.SanitizeSQL,
		SanitizeNoSQL:     config.SanitizeNoSQL,
		SanitizePath:      config.SanitizePath,
		SanitizeCmd:       config.SanitizeCmd,
		MaxInputSize:      config.MaxInputSize,
		RateLimit:         config.RateLimit,
		RateLimitMax:      config.RateLimitMax,
		RateLimitWindow:   config.RateLimitWindow,
		Headers:           config.Headers,
		CSP:               config.CSP,
		FrameOptions:      config.FrameOptions,
		HSTSMaxAge:        config.HSTSMaxAge,
		HSTSSubdomains:    config.HSTSSubdomains,
		ReferrerPolicy:    config.ReferrerPolicy,
		PermissionsPolicy: config.PermissionsPolicy,
		CacheControl:      config.CacheControl,
		IsDev:             config.IsDev,
	}

	sanitizer := shield.NewSanitizer(shieldConfig)
	instance := &shieldInstance{}

	var rateLimiter *shield.RateLimiter
	if config.RateLimit {
		rateLimiter = shield.NewRateLimiter(config.RateLimitMax, config.RateLimitWindow)
		instance.rateLimiter = rateLimiter
	}

	var securityHeaders *shield.SecurityHeaders
	if config.Headers {
		securityHeaders = shield.NewSecurityHeaders(shieldConfig)
	}

	activeInstances = append(activeInstances, instance)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip function check for rate limiting
			skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

			if !skipRateLimit && rateLimiter != nil {
				result := rateLimiter.Check(c.Request())

				c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

				if !result.Allowed {
					c.Response().Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
					return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
						"error":      "Too many requests, please try again later.",
						"retryAfter": int(result.Reset.Seconds()),
					})
				}
			}

			// Security headers
			if securityHeaders != nil {
				for key, value := range securityHeaders.GetHeaders() {
					c.Response().Header().Set(key, value)
				}
			}

			// Remove fingerprinting headers
			c.Response().Header().Del("Server")
			c.Response().Header().Del("X-Powered-By")

			// Store sanitizer in context for use in handlers
			c.Set(SanitizerKey, sanitizer)

			return next(c)
		}
	}
}

// Headers returns a middleware that only sets security headers.
func Headers() echo.MiddlewareFunc {
	return HeadersWithConfig(DefaultConfig())
}

// HeadersWithConfig returns a headers middleware with custom configuration.
func HeadersWithConfig(config Config) echo.MiddlewareFunc {
	shieldConfig := shield.Config{
		CSP:               config.CSP,
		FrameOptions:      config.FrameOptions,
		HSTSMaxAge:        config.HSTSMaxAge,
		HSTSSubdomains:    config.HSTSSubdomains,
		ReferrerPolicy:    config.ReferrerPolicy,
		PermissionsPolicy: config.PermissionsPolicy,
		CacheControl:      config.CacheControl,
	}

	headers := shield.NewSecurityHeaders(shieldConfig)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			for key, value := range headers.GetHeaders() {
				c.Response().Header().Set(key, value)
			}
			c.Response().Header().Del("Server")
			c.Response().Header().Del("X-Powered-By")
			return next(c)
		}
	}
}

// RateLimit returns a middleware for rate limiting with specified limits.
func RateLimit(max int, window time.Duration) echo.MiddlewareFunc {
	return RateLimitWithSkip(max, window, nil)
}

// RateLimitWithSkip returns a rate limiting middleware with custom skip function.
func RateLimitWithSkip(max int, window time.Duration, skip func(echo.Context) bool) echo.MiddlewareFunc {
	limiter := shield.NewRateLimiter(max, window)
	instance := &shieldInstance{rateLimiter: limiter}
	activeInstances = append(activeInstances, instance)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if skip != nil && skip(c) {
				return next(c)
			}

			result := limiter.Check(c.Request())

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				c.Response().Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
			}

			return next(c)
		}
	}
}

// Sanitizer returns a middleware that provides sanitization utilities.
func Sanitizer() echo.MiddlewareFunc {
	return SanitizerWithConfig(DefaultConfig())
}

// SanitizerWithConfig returns a sanitizer middleware with custom configuration.
func SanitizerWithConfig(config Config) echo.MiddlewareFunc {
	shieldConfig := shield.Config{
		SanitizeXSS:   config.SanitizeXSS,
		SanitizeSQL:   config.SanitizeSQL,
		SanitizeNoSQL: config.SanitizeNoSQL,
		SanitizePath:  config.SanitizePath,
		SanitizeCmd:   config.SanitizeCmd,
		MaxInputSize:  config.MaxInputSize,
	}

	sanitizer := shield.NewSanitizer(shieldConfig)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(SanitizerKey, sanitizer)
			return next(c)
		}
	}
}

// GetSanitizer retrieves the Shield sanitizer from the Echo context.
func GetSanitizer(c echo.Context) *shield.Sanitizer {
	if s := c.Get(SanitizerKey); s != nil {
		return s.(*shield.Sanitizer)
	}
	return shield.NewSanitizer(shield.DefaultConfig())
}

// SanitizeJSON sanitizes JSON data using the sanitizer from context.
//
// Example:
//
//	func handler(c echo.Context) error {
//	    var data map[string]interface{}
//	    if err := c.Bind(&data); err != nil {
//	        return c.JSON(400, map[string]string{"error": err.Error()})
//	    }
//	    data = shieldecho.SanitizeJSON(c, data)
//	    // Use sanitized data...
//	}
func SanitizeJSON(c echo.Context, data map[string]interface{}) map[string]interface{} {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeMap(data)
}

// SanitizeString sanitizes a string value using the sanitizer from context.
func SanitizeString(c echo.Context, value string) string {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeString(value)
}

// Validate creates a validation middleware using Shield's validator.
func Validate(schema shield.ValidationSchema) echo.MiddlewareFunc {
	validator := shield.NewValidator(schema)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var data map[string]interface{}
			if err := c.Bind(&data); err != nil {
				return c.JSON(http.StatusBadRequest, map[string]interface{}{
					"errors": []string{"Invalid JSON"},
				})
			}

			validated, validationErr := validator.Validate(data)
			if validationErr != nil {
				return c.JSON(http.StatusBadRequest, map[string]interface{}{
					"errors": validationErr.Errors,
				})
			}

			c.Set(ValidatedBodyKey, validated)
			return next(c)
		}
	}
}

// GetValidatedBody retrieves the validated request body from the context.
func GetValidatedBody(c echo.Context) map[string]interface{} {
	if v := c.Get(ValidatedBodyKey); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

// ErrorHandler returns an Echo error handler function.
// Use with e.HTTPErrorHandler = shieldecho.ErrorHandler(isDev)
func ErrorHandler(isDev bool) echo.HTTPErrorHandler {
	handler := shield.NewErrorHandler(isDev)

	return func(err error, c echo.Context) {
		if c.Response().Committed {
			return
		}

		statusCode := http.StatusInternalServerError
		if he, ok := err.(*echo.HTTPError); ok {
			statusCode = he.Code
		}

		handler.Handle(c.Response().Writer, err, statusCode)
	}
}

// ErrorMiddleware returns middleware that catches errors and handles them safely.
func ErrorMiddleware(isDev bool) echo.MiddlewareFunc {
	handler := shield.NewErrorHandler(isDev)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			err := next(c)
			if err != nil {
				statusCode := http.StatusInternalServerError
				if he, ok := err.(*echo.HTTPError); ok {
					statusCode = he.Code
				}
				handler.Handle(c.Response().Writer, err, statusCode)
				return nil // Error has been handled
			}
			return nil
		}
	}
}
