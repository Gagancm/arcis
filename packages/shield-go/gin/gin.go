/*
Package gin provides Shield middleware adapters for the Gin web framework.

Usage:

	import (
		"github.com/gin-gonic/gin"
		shieldgin "github.com/aspect.dev/shield-go/gin"
	)

	func main() {
		r := gin.Default()

		// Full protection with defaults
		r.Use(shieldgin.Middleware())

		// Or with custom config
		r.Use(shieldgin.MiddlewareWithConfig(shieldgin.Config{
			RateLimitMax:    50,
			RateLimitWindow: time.Minute,
			CSP:             "default-src 'self'",
		}))

		// Granular middleware
		r.Use(shieldgin.Headers())
		r.Use(shieldgin.RateLimit(100, time.Minute))
		r.Use(shieldgin.Sanitizer())

		r.GET("/", handler)
		r.Run(":8080")
	}

# Resource Cleanup

Shield's rate limiter runs a background goroutine for cleanup. Call Cleanup()
when your application shuts down to stop this goroutine and release resources:

	import (
		"context"
		"os/signal"
		"syscall"
		shieldgin "github.com/aspect.dev/shield-go/gin"
	)

	func main() {
		r := gin.Default()
		r.Use(shieldgin.Middleware())

		// Graceful shutdown
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go r.Run(":8080")

		<-ctx.Done()
		shieldgin.Cleanup() // Stop rate limiter background goroutines
	}

Alternatively, register cleanup with a defer or shutdown hook:

	func main() {
		defer shieldgin.Cleanup()
		// ... rest of setup
	}
*/
package gin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	shield "github.com/aspect.dev/shield-go"
)

// Config holds Shield middleware configuration for Gin.
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
	RateLimitSkip   func(*gin.Context) bool

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

// DefaultConfig returns the default Shield configuration for Gin.
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
//		defer shieldgin.Cleanup()
//		r := gin.Default()
//		r.Use(shieldgin.Middleware())
//		r.Run(":8080")
//	}
//
// For graceful shutdown with signal handling:
//
//	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
//	defer stop()
//	go r.Run(":8080")
//	<-ctx.Done()
//	shieldgin.Cleanup()
func Cleanup() {
	for _, instance := range activeInstances {
		instance.Close()
	}
	activeInstances = nil
}

// Middleware returns a Gin middleware with default Shield configuration.
func Middleware() gin.HandlerFunc {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns a Gin middleware with custom configuration.
func MiddlewareWithConfig(config Config) gin.HandlerFunc {
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

	return func(c *gin.Context) {
		// Skip function check for rate limiting
		skipRateLimit := config.RateLimitSkip != nil && config.RateLimitSkip(c)

		if !skipRateLimit && rateLimiter != nil {
			result := rateLimiter.Check(c.Request)

			c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}
		}

		// Security headers
		if securityHeaders != nil {
			for key, value := range securityHeaders.GetHeaders() {
				c.Header(key, value)
			}
		}

		// Remove fingerprinting headers
		c.Writer.Header().Del("Server")
		c.Writer.Header().Del("X-Powered-By")

		// Store sanitizer in context for use in handlers
		c.Set("shield_sanitizer", sanitizer)

		c.Next()
	}
}

// Headers returns a middleware that only sets security headers.
func Headers() gin.HandlerFunc {
	return HeadersWithConfig(DefaultConfig())
}

// HeadersWithConfig returns a headers middleware with custom configuration.
func HeadersWithConfig(config Config) gin.HandlerFunc {
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

	return func(c *gin.Context) {
		for key, value := range headers.GetHeaders() {
			c.Header(key, value)
		}
		c.Writer.Header().Del("Server")
		c.Writer.Header().Del("X-Powered-By")
		c.Next()
	}
}

// RateLimit returns a middleware for rate limiting with specified limits.
func RateLimit(max int, window time.Duration) gin.HandlerFunc {
	return RateLimitWithSkip(max, window, nil)
}

// RateLimitWithSkip returns a rate limiting middleware with custom skip function.
func RateLimitWithSkip(max int, window time.Duration, skip func(*gin.Context) bool) gin.HandlerFunc {
	limiter := shield.NewRateLimiter(max, window)
	instance := &shieldInstance{rateLimiter: limiter}
	activeInstances = append(activeInstances, instance)

	return func(c *gin.Context) {
		if skip != nil && skip(c) {
			c.Next()
			return
		}

		result := limiter.Check(c.Request)

		c.Header("X-RateLimit-Limit", strconv.Itoa(result.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
		c.Header("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

		if !result.Allowed {
			c.Header("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":      "Too many requests, please try again later.",
				"retryAfter": int(result.Reset.Seconds()),
			})
			return
		}

		c.Next()
	}
}

// Sanitizer returns a middleware that provides sanitization utilities.
func Sanitizer() gin.HandlerFunc {
	return SanitizerWithConfig(DefaultConfig())
}

// SanitizerWithConfig returns a sanitizer middleware with custom configuration.
func SanitizerWithConfig(config Config) gin.HandlerFunc {
	shieldConfig := shield.Config{
		SanitizeXSS:   config.SanitizeXSS,
		SanitizeSQL:   config.SanitizeSQL,
		SanitizeNoSQL: config.SanitizeNoSQL,
		SanitizePath:  config.SanitizePath,
		SanitizeCmd:   config.SanitizeCmd,
		MaxInputSize:  config.MaxInputSize,
	}

	sanitizer := shield.NewSanitizer(shieldConfig)

	return func(c *gin.Context) {
		c.Set("shield_sanitizer", sanitizer)
		c.Next()
	}
}

// GetSanitizer retrieves the Shield sanitizer from the Gin context.
func GetSanitizer(c *gin.Context) *shield.Sanitizer {
	if s, exists := c.Get("shield_sanitizer"); exists {
		return s.(*shield.Sanitizer)
	}
	return shield.NewSanitizer(shield.DefaultConfig())
}

// SanitizeJSON sanitizes JSON data using the sanitizer from context.
//
// Example:
//
//	func handler(c *gin.Context) {
//	    var data map[string]interface{}
//	    if err := c.ShouldBindJSON(&data); err != nil {
//	        c.JSON(400, gin.H{"error": err.Error()})
//	        return
//	    }
//	    data = shieldgin.SanitizeJSON(c, data)
//	    // Use sanitized data...
//	}
func SanitizeJSON(c *gin.Context, data map[string]interface{}) map[string]interface{} {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeMap(data)
}

// SanitizeString sanitizes a string value using the sanitizer from context.
func SanitizeString(c *gin.Context, value string) string {
	sanitizer := GetSanitizer(c)
	return sanitizer.SanitizeString(value)
}

// Validate creates a validation middleware using Shield's validator.
func Validate(schema shield.ValidationSchema) gin.HandlerFunc {
	validator := shield.NewValidator(schema)

	return func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"errors": []string{"Invalid JSON"},
			})
			return
		}

		validated, validationErr := validator.Validate(data)
		if validationErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"errors": validationErr.Errors,
			})
			return
		}

		c.Set("validated_body", validated)
		c.Next()
	}
}

// GetValidatedBody retrieves the validated request body from the context.
func GetValidatedBody(c *gin.Context) map[string]interface{} {
	if v, exists := c.Get("validated_body"); exists {
		return v.(map[string]interface{})
	}
	return nil
}

// ErrorHandler returns a Gin error handler middleware.
func ErrorHandler(isDev bool) gin.HandlerFunc {
	handler := shield.NewErrorHandler(isDev)

	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			statusCode := c.Writer.Status()
			if statusCode == 0 || statusCode == http.StatusOK {
				statusCode = http.StatusInternalServerError
			}
			handler.Handle(c.Writer, err, statusCode)
		}
	}
}
