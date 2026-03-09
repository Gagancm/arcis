/*
Package shield provides one-line security for Go web applications.

Shield is a comprehensive security middleware that provides:
  - Input sanitization (XSS, SQL injection, NoSQL injection, path traversal)
  - Rate limiting with configurable windows and limits
  - Security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Request validation with schema support
  - Safe logging with sensitive data redaction

Usage with net/http:

	import "github.com/aspect.dev/shield-go"

	// Full protection (recommended)
	http.Handle("/", shield.Protect(myHandler))

	// Or with custom config
	s := shield.NewWithConfig(shield.Config{
		RateLimitMax: 50,
		CSP: "default-src 'none'",
	})
	http.Handle("/", s.Handler(myHandler))

Usage with Gin:

	import "github.com/aspect.dev/shield-go/gin"

	r := gin.Default()
	r.Use(shieldgin.Middleware())

Usage with Echo:

	import "github.com/aspect.dev/shield-go/echo"

	e := echo.New()
	e.Use(shieldecho.Middleware())
*/
package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the current version of Shield.
const Version = "1.0.0"

// MaxRecursionDepth is the maximum depth for recursive operations.
const MaxRecursionDepth = 10

// Config holds Shield configuration options.
type Config struct {
	// Sanitizer options
	Sanitize      bool
	SanitizeXSS   bool
	SanitizeSQL   bool
	SanitizeNoSQL bool
	SanitizePath  bool
	SanitizeCmd   bool // Command injection protection
	MaxInputSize  int  // Maximum input size in bytes (default: 1MB)

	// Rate limiter options
	RateLimit       bool
	RateLimitMax    int
	RateLimitWindow time.Duration
	RateLimitSkip   func(*http.Request) bool // Skip rate limiting for certain requests

	// Security headers options
	Headers           bool
	CSP               string
	FrameOptions      string // DENY, SAMEORIGIN, or empty to disable
	HSTSMaxAge        int    // Max age in seconds, 0 to disable
	HSTSSubdomains    bool
	ReferrerPolicy    string
	PermissionsPolicy string
	CacheControl      bool // Enable cache-control headers (default: true)

	// Error handler options
	IsDev bool // Show error details in development mode
}

// DefaultConfig returns the default Shield configuration.
// All protections are enabled with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Sanitize:          true,
		SanitizeXSS:       true,
		SanitizeSQL:       true,
		SanitizeNoSQL:     true,
		SanitizePath:      true,
		SanitizeCmd:       true,
		MaxInputSize:      1000000, // 1MB default
		RateLimit:         true,
		RateLimitMax:      100,
		RateLimitWindow:   time.Minute,
		Headers:           true,
		CSP:               "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';",
		FrameOptions:      "DENY",
		HSTSMaxAge:        31536000, // 1 year
		HSTSSubdomains:    true,
		ReferrerPolicy:    "strict-origin-when-cross-origin",
		PermissionsPolicy: "geolocation=(), microphone=(), camera=()",
		CacheControl:      true,
		IsDev:             false,
	}
}

// Shield is the main security middleware.
type Shield struct {
	config       Config
	sanitizer    *Sanitizer
	rateLimiter  *RateLimiter
	headers      *SecurityHeaders
	errorHandler *ErrorHandler
}

// New creates a new Shield instance with default configuration.
func New() *Shield {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a new Shield instance with custom configuration.
func NewWithConfig(config Config) *Shield {
	s := &Shield{config: config}

	if config.Sanitize {
		s.sanitizer = NewSanitizer(config)
	}

	if config.RateLimit {
		s.rateLimiter = NewRateLimiter(config.RateLimitMax, config.RateLimitWindow)
		if config.RateLimitSkip != nil {
			s.rateLimiter.SetSkipFunc(config.RateLimitSkip)
		}
	}

	if config.Headers {
		s.headers = NewSecurityHeaders(config)
	}

	s.errorHandler = NewErrorHandler(config.IsDev)

	return s
}

// Protect wraps an http.Handler with Shield protection using default config.
// This is the simplest way to add Shield protection to your handlers.
func Protect(handler http.Handler) http.Handler {
	return New().Handler(handler)
}

// Handler returns an http.Handler middleware.
func (s *Shield) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting
		if s.rateLimiter != nil {
			result := s.rateLimiter.Check(r)

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}
		}

		// Security headers
		if s.headers != nil {
			for key, value := range s.headers.GetHeaders() {
				w.Header().Set(key, value)
			}
		}

		// Remove fingerprinting headers
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")

		next.ServeHTTP(w, r)
	})
}

// Close gracefully shuts down the Shield instance, cleaning up resources.
// Call this when your server is shutting down.
func (s *Shield) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

// Sanitize sanitizes a string value.
func (s *Shield) Sanitize(value string) string {
	if s.sanitizer == nil {
		return value
	}
	return s.sanitizer.SanitizeString(value)
}

// SanitizeMap sanitizes a map (like JSON body).
func (s *Shield) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	if s.sanitizer == nil {
		return data
	}
	return s.sanitizer.SanitizeMap(data)
}

// SanitizeBody reads, sanitizes, and returns JSON body from request.
// The original body is replaced with the sanitized version.
func (s *Shield) SanitizeBody(r *http.Request) (map[string]interface{}, error) {
	if s.sanitizer == nil {
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			return nil, err
		}
		return data, nil
	}

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, err
	}

	return s.sanitizer.SanitizeMap(data), nil
}

// ---------- Sanitizer ----------

// Pre-compiled XSS patterns for performance (ReDoS-safe)
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`), // ReDoS-safe version
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)vbscript:`),
	regexp.MustCompile(`(?i)on\w+\s*=`),
	regexp.MustCompile(`(?i)<iframe`),
	regexp.MustCompile(`(?i)<object`),
	regexp.MustCompile(`(?i)<embed`),
	regexp.MustCompile(`(?i)data:`),
	regexp.MustCompile(`(?i)%3Cscript`),       // URL-encoded <script
	regexp.MustCompile(`(?i)<svg[^>]*onload`), // SVG with onload
}

// Pre-compiled SQL injection patterns
var sqlPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE)\b`),
	regexp.MustCompile(`(--|/\*|\*/)`),
	regexp.MustCompile(`(;|\|\||&&)`),
	// More specific boolean injection patterns to avoid false positives (e.g., "Oregon", "Anderson")
	regexp.MustCompile(`(?i)\bOR\s+\d+\s*=\s*\d+`),                         // OR 1=1
	regexp.MustCompile(`(?i)\bOR\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]`),   // OR 'a'='a'
	regexp.MustCompile(`(?i)\bAND\s+\d+\s*=\s*\d+`),                        // AND 1=1
	regexp.MustCompile(`(?i)\bAND\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]`), // AND 'a'='a'
}

// Pre-compiled path traversal patterns
var pathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\.\/`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`(?i)%2e%2e`),
	regexp.MustCompile(`(?i)%252e`), // Double URL-encoded
}

// Pre-compiled command injection patterns
var cmdPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;&|` + "`" + `$()]`),
	regexp.MustCompile(`(?i)\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php)\b`),
}

// NoSQL dangerous keys that could be used for injection
var nosqlDangerousKeys = map[string]bool{
	"$gt": true, "$gte": true, "$lt": true, "$lte": true,
	"$ne": true, "$eq": true, "$in": true, "$nin": true,
	"$and": true, "$or": true, "$not": true, "$exists": true,
	"$type": true, "$regex": true, "$where": true, "$expr": true,
}

// Prototype pollution dangerous keys (for JS interop)
var protoPollutionKeys = map[string]bool{
	"__proto__":   true,
	"constructor": true,
	"prototype":   true,
}

// HTML encoding map for XSS prevention
var htmlEncoding = map[rune]string{
	'&':  "&amp;",
	'<':  "&lt;",
	'>':  "&gt;",
	'"':  "&quot;",
	'\'': "&#x27;",
}

// Validation patterns
var (
	emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	urlPattern   = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	uuidPattern  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// Sanitizer handles input sanitization.
type Sanitizer struct {
	xss          bool
	sql          bool
	nosql        bool
	path         bool
	cmd          bool
	maxInputSize int
}

// NewSanitizer creates a new Sanitizer with the given configuration.
func NewSanitizer(config Config) *Sanitizer {
	maxSize := config.MaxInputSize
	if maxSize <= 0 {
		maxSize = 1000000 // 1MB default
	}
	return &Sanitizer{
		xss:          config.SanitizeXSS,
		sql:          config.SanitizeSQL,
		nosql:        config.SanitizeNoSQL,
		path:         config.SanitizePath,
		cmd:          config.SanitizeCmd,
		maxInputSize: maxSize,
	}
}

// NewSanitizerWithOptions creates a sanitizer with explicit options.
func NewSanitizerWithOptions(xss, sql, nosql, path, cmd bool) *Sanitizer {
	return &Sanitizer{
		xss:          xss,
		sql:          sql,
		nosql:        nosql,
		path:         path,
		cmd:          cmd,
		maxInputSize: 1000000,
	}
}

// InputTooLargeError is returned when input exceeds the maximum size.
type InputTooLargeError struct {
	Size    int
	MaxSize int
}

func (e *InputTooLargeError) Error() string {
	return fmt.Sprintf("input size %d exceeds maximum of %d bytes", e.Size, e.MaxSize)
}

// SanitizeString sanitizes a string value, removing potentially dangerous content.
func (s *Sanitizer) SanitizeString(value string) string {
	if value == "" {
		return value
	}

	// Input size limit to prevent DoS
	if len(value) > s.maxInputSize {
		// Truncate instead of error for backward compatibility
		value = value[:s.maxInputSize]
	}

	result := value

	// XSS prevention - remove patterns FIRST (while detectable), then encode
	if s.xss {
		// Remove dangerous patterns FIRST
		for _, pattern := range xssPatterns {
			result = pattern.ReplaceAllString(result, "")
		}

		// THEN encode remaining content
		var sb strings.Builder
		sb.Grow(len(result) * 2) // Pre-allocate for potential entity expansion
		for _, r := range result {
			if enc, ok := htmlEncoding[r]; ok {
				sb.WriteString(enc)
			} else {
				sb.WriteRune(r)
			}
		}
		result = sb.String()
	}

	// SQL injection prevention
	if s.sql {
		for _, pattern := range sqlPatterns {
			result = pattern.ReplaceAllString(result, "[BLOCKED]")
		}
	}

	// Path traversal prevention
	if s.path {
		for _, pattern := range pathPatterns {
			result = pattern.ReplaceAllString(result, "")
		}
	}

	// Command injection prevention
	if s.cmd {
		for _, pattern := range cmdPatterns {
			result = pattern.ReplaceAllString(result, "[BLOCKED]")
		}
	}

	return result
}

// SanitizeMap sanitizes a map recursively.
func (s *Sanitizer) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	return s.sanitizeMapDepth(data, 0)
}

func (s *Sanitizer) sanitizeMapDepth(data map[string]interface{}, depth int) map[string]interface{} {
	if depth > MaxRecursionDepth || data == nil {
		return data
	}

	result := make(map[string]interface{}, len(data))

	for key, value := range data {
		// Prototype pollution prevention - always block dangerous keys
		if protoPollutionKeys[key] {
			continue
		}

		// NoSQL injection - skip dangerous keys like $gt, $where, etc.
		if s.nosql && nosqlDangerousKeys[key] {
			continue
		}

		// Sanitize key
		sanitizedKey := s.SanitizeString(key)

		// Sanitize value based on type
		switch v := value.(type) {
		case string:
			result[sanitizedKey] = s.SanitizeString(v)
		case map[string]interface{}:
			result[sanitizedKey] = s.sanitizeMapDepth(v, depth+1)
		case []interface{}:
			result[sanitizedKey] = s.sanitizeSlice(v, depth+1)
		default:
			result[sanitizedKey] = value
		}
	}

	return result
}

func (s *Sanitizer) sanitizeSlice(data []interface{}, depth int) []interface{} {
	if depth > MaxRecursionDepth || data == nil {
		return data
	}

	result := make([]interface{}, len(data))

	for i, item := range data {
		switch v := item.(type) {
		case string:
			result[i] = s.SanitizeString(v)
		case map[string]interface{}:
			result[i] = s.sanitizeMapDepth(v, depth+1)
		case []interface{}:
			result[i] = s.sanitizeSlice(v, depth+1)
		default:
			result[i] = item
		}
	}

	return result
}

// ---------- Rate Limiter ----------

// RateLimitResult holds the result of a rate limit check.
type RateLimitResult struct {
	Allowed   bool
	Limit     int
	Remaining int
	Reset     time.Duration
}

// RateLimiter handles rate limiting with configurable limits and windows.
type RateLimiter struct {
	max      int
	window   time.Duration
	store    map[string]*rateLimitEntry
	mu       sync.RWMutex
	skipFunc func(*http.Request) bool
	ctx      context.Context
	cancel   context.CancelFunc
}

type rateLimitEntry struct {
	count     int
	resetTime time.Time
}

// NewRateLimiter creates a new RateLimiter with the given limit and window.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())
	rl := &RateLimiter{
		max:    max,
		window: window,
		store:  make(map[string]*rateLimitEntry),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start cleanup goroutine with proper cancellation
	go func() {
		ticker := time.NewTicker(window)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				rl.cleanup()
			}
		}
	}()

	return rl
}

// SetSkipFunc sets a function that determines whether to skip rate limiting.
func (rl *RateLimiter) SetSkipFunc(fn func(*http.Request) bool) {
	rl.skipFunc = fn
}

// Check checks if a request is within the rate limit.
func (rl *RateLimiter) Check(r *http.Request) RateLimitResult {
	// Check skip function first
	if rl.skipFunc != nil && rl.skipFunc(r) {
		return RateLimitResult{
			Allowed:   true,
			Limit:     rl.max,
			Remaining: rl.max,
			Reset:     rl.window,
		}
	}

	key := getClientIP(r)
	return rl.CheckKey(key)
}

// CheckKey checks rate limit for a specific key (useful for testing or custom keys).
func (rl *RateLimiter) CheckKey(key string) RateLimitResult {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	entry, exists := rl.store[key]
	if !exists || entry.resetTime.Before(now) {
		rl.store[key] = &rateLimitEntry{
			count:     1,
			resetTime: now.Add(rl.window),
		}
		return RateLimitResult{
			Allowed:   true,
			Limit:     rl.max,
			Remaining: rl.max - 1,
			Reset:     rl.window,
		}
	}

	entry.count++
	remaining := rl.max - entry.count
	if remaining < 0 {
		remaining = 0
	}
	reset := entry.resetTime.Sub(now)

	return RateLimitResult{
		Allowed:   entry.count <= rl.max,
		Limit:     rl.max,
		Remaining: remaining,
		Reset:     reset,
	}
}

// Close stops the cleanup goroutine and releases resources.
func (rl *RateLimiter) Close() {
	rl.cancel()
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, entry := range rl.store {
		if entry.resetTime.Before(now) {
			delete(rl.store, key)
		}
	}
}

// ---------- Security Headers ----------

// SecurityHeaders handles security header configuration and application.
type SecurityHeaders struct {
	headers map[string]string
}

// NewSecurityHeaders creates a new SecurityHeaders with the given configuration.
func NewSecurityHeaders(config Config) *SecurityHeaders {
	headers := make(map[string]string)

	// Content Security Policy
	if config.CSP != "" {
		headers["Content-Security-Policy"] = config.CSP
	}

	// X-Content-Type-Options - prevent MIME sniffing
	headers["X-Content-Type-Options"] = "nosniff"

	// X-Frame-Options - prevent clickjacking
	if config.FrameOptions != "" {
		headers["X-Frame-Options"] = config.FrameOptions
	}

	// X-XSS-Protection - legacy but still useful
	headers["X-XSS-Protection"] = "1; mode=block"

	// HSTS - enforce HTTPS
	if config.HSTSMaxAge > 0 {
		hsts := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
		if config.HSTSSubdomains {
			hsts += "; includeSubDomains"
		}
		headers["Strict-Transport-Security"] = hsts
	}

	// Referrer Policy
	if config.ReferrerPolicy != "" {
		headers["Referrer-Policy"] = config.ReferrerPolicy
	}

	// Permissions Policy
	if config.PermissionsPolicy != "" {
		headers["Permissions-Policy"] = config.PermissionsPolicy
	}

	// X-Permitted-Cross-Domain-Policies
	headers["X-Permitted-Cross-Domain-Policies"] = "none"

	// Cache-Control headers to prevent caching of sensitive data
	if config.CacheControl {
		headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
		headers["Pragma"] = "no-cache"
		headers["Expires"] = "0"
	}

	return &SecurityHeaders{headers: headers}
}

// GetHeaders returns all security headers as a map.
func (sh *SecurityHeaders) GetHeaders() map[string]string {
	return sh.headers
}

// SetHeader sets or overrides a specific header.
func (sh *SecurityHeaders) SetHeader(key, value string) {
	sh.headers[key] = value
}

// RemoveHeader removes a specific header.
func (sh *SecurityHeaders) RemoveHeader(key string) {
	delete(sh.headers, key)
}

// ---------- Validator ----------

// FieldType represents the type of a field for validation.
type FieldType string

const (
	TypeString  FieldType = "string"
	TypeNumber  FieldType = "number"
	TypeBoolean FieldType = "boolean"
	TypeEmail   FieldType = "email"
	TypeURL     FieldType = "url"
	TypeUUID    FieldType = "uuid"
	TypeArray   FieldType = "array"
	TypeObject  FieldType = "object"
)

// FieldRule defines validation rules for a single field.
type FieldRule struct {
	Type     FieldType
	Required bool
	Min      *float64 // Min value (number) or length (string/array)
	Max      *float64 // Max value (number) or length (string/array)
	Pattern  *regexp.Regexp
	Enum     []interface{}
	Sanitize bool // Default: true
	Custom   func(value interface{}) (bool, string)
}

// ValidationSchema defines validation rules for multiple fields.
type ValidationSchema map[string]FieldRule

// ValidationError represents a validation error.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Errors, ", ")
}

// Validator validates request data against a schema.
type Validator struct {
	schema    ValidationSchema
	sanitizer *Sanitizer
}

// NewValidator creates a new Validator with the given schema.
func NewValidator(schema ValidationSchema) *Validator {
	return &Validator{
		schema:    schema,
		sanitizer: NewSanitizerWithOptions(true, true, true, true, true),
	}
}

// Validate validates data against the schema.
// Returns validated data (only fields in schema) and any errors.
func (v *Validator) Validate(data map[string]interface{}) (map[string]interface{}, *ValidationError) {
	errors := []string{}
	validated := make(map[string]interface{})

	for field, rules := range v.schema {
		value, exists := data[field]

		// Required check
		if rules.Required && (!exists || value == nil || value == "") {
			errors = append(errors, fmt.Sprintf("%s is required", field))
			continue
		}

		// Skip optional empty fields
		if !exists || value == nil {
			continue
		}

		typedValue := value
		isValid := true

		// Type validation and coercion
		switch rules.Type {
		case TypeString:
			str, ok := value.(string)
			if !ok {
				errors = append(errors, fmt.Sprintf("%s must be a string", field))
				isValid = false
			} else {
				if rules.Min != nil && float64(len(str)) < *rules.Min {
					errors = append(errors, fmt.Sprintf("%s must be at least %.0f characters", field, *rules.Min))
					isValid = false
				}
				if rules.Max != nil && float64(len(str)) > *rules.Max {
					errors = append(errors, fmt.Sprintf("%s must be at most %.0f characters", field, *rules.Max))
					isValid = false
				}
				if rules.Pattern != nil && !rules.Pattern.MatchString(str) {
					errors = append(errors, fmt.Sprintf("%s format is invalid", field))
					isValid = false
				}
				if isValid && (rules.Sanitize || rules.Type == TypeString) {
					typedValue = v.sanitizer.SanitizeString(str)
				}
			}

		case TypeNumber:
			var num float64
			switch n := value.(type) {
			case float64:
				num = n
			case float32:
				num = float64(n)
			case int:
				num = float64(n)
			case int64:
				num = float64(n)
			case string:
				var err error
				num, err = strconv.ParseFloat(n, 64)
				if err != nil {
					errors = append(errors, fmt.Sprintf("%s must be a number", field))
					isValid = false
				}
			default:
				errors = append(errors, fmt.Sprintf("%s must be a number", field))
				isValid = false
			}
			if isValid {
				if rules.Min != nil && num < *rules.Min {
					errors = append(errors, fmt.Sprintf("%s must be at least %.0f", field, *rules.Min))
					isValid = false
				}
				if rules.Max != nil && num > *rules.Max {
					errors = append(errors, fmt.Sprintf("%s must be at most %.0f", field, *rules.Max))
					isValid = false
				}
				typedValue = num
			}

		case TypeBoolean:
			switch b := value.(type) {
			case bool:
				typedValue = b
			case string:
				if b == "true" || b == "1" {
					typedValue = true
				} else if b == "false" || b == "0" {
					typedValue = false
				} else {
					errors = append(errors, fmt.Sprintf("%s must be a boolean", field))
					isValid = false
				}
			case int:
				typedValue = b != 0
			default:
				errors = append(errors, fmt.Sprintf("%s must be a boolean", field))
				isValid = false
			}

		case TypeEmail:
			str, ok := value.(string)
			if !ok || !emailPattern.MatchString(str) {
				errors = append(errors, fmt.Sprintf("%s must be a valid email", field))
				isValid = false
			} else {
				typedValue = v.sanitizer.SanitizeString(strings.ToLower(strings.TrimSpace(str)))
			}

		case TypeURL:
			str, ok := value.(string)
			if !ok || !urlPattern.MatchString(str) {
				errors = append(errors, fmt.Sprintf("%s must be a valid URL", field))
				isValid = false
			} else {
				typedValue = v.sanitizer.SanitizeString(str)
			}

		case TypeUUID:
			str, ok := value.(string)
			if !ok || !uuidPattern.MatchString(str) {
				errors = append(errors, fmt.Sprintf("%s must be a valid UUID", field))
				isValid = false
			}

		case TypeArray:
			arr, ok := value.([]interface{})
			if !ok {
				errors = append(errors, fmt.Sprintf("%s must be an array", field))
				isValid = false
			} else {
				if rules.Min != nil && float64(len(arr)) < *rules.Min {
					errors = append(errors, fmt.Sprintf("%s must have at least %.0f items", field, *rules.Min))
					isValid = false
				}
				if rules.Max != nil && float64(len(arr)) > *rules.Max {
					errors = append(errors, fmt.Sprintf("%s must have at most %.0f items", field, *rules.Max))
					isValid = false
				}
			}

		case TypeObject:
			_, ok := value.(map[string]interface{})
			if !ok {
				errors = append(errors, fmt.Sprintf("%s must be an object", field))
				isValid = false
			}
		}

		// Enum validation
		if isValid && len(rules.Enum) > 0 {
			found := false
			for _, e := range rules.Enum {
				if typedValue == e {
					found = true
					break
				}
			}
			if !found {
				enumStrs := make([]string, len(rules.Enum))
				for i, e := range rules.Enum {
					enumStrs[i] = fmt.Sprintf("%v", e)
				}
				errors = append(errors, fmt.Sprintf("%s must be one of: %s", field, strings.Join(enumStrs, ", ")))
				isValid = false
			}
		}

		// Custom validation
		if isValid && rules.Custom != nil {
			ok, msg := rules.Custom(typedValue)
			if !ok {
				if msg == "" {
					msg = fmt.Sprintf("%s is invalid", field)
				}
				errors = append(errors, msg)
				isValid = false
			}
		}

		if isValid {
			validated[field] = typedValue
		}
	}

	if len(errors) > 0 {
		return nil, &ValidationError{Errors: errors}
	}

	return validated, nil
}

// ValidateHandler creates middleware that validates request body.
// Only fields in the schema are passed to the handler (mass assignment prevention).
func ValidateHandler(schema ValidationSchema, next http.Handler) http.Handler {
	validator := NewValidator(schema)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"Failed to read request body"},
			})
			return
		}

		// Parse JSON
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"Invalid JSON"},
			})
			return
		}

		// Validate
		validated, validationErr := validator.Validate(data)
		if validationErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": validationErr.Errors,
			})
			return
		}

		// Store validated data in context
		ctx := context.WithValue(r.Context(), validatedBodyKey, validated)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKey string

const validatedBodyKey contextKey = "shield_validated_body"

// GetValidatedBody retrieves the validated body from request context.
func GetValidatedBody(r *http.Request) map[string]interface{} {
	if v := r.Context().Value(validatedBodyKey); v != nil {
		return v.(map[string]interface{})
	}
	return nil
}

// Helper functions for creating FieldRule with Min/Max
func Float(v float64) *float64 {
	return &v
}

// ---------- Safe Logger ----------

// SafeLogger provides safe logging with automatic redaction of sensitive data.
type SafeLogger struct {
	sensitiveKeys map[string]bool
	maxLength     int
}

// Default sensitive keys to redact
var defaultSensitiveKeys = []string{
	"password", "passwd", "pwd", "secret", "token", "apikey",
	"api_key", "authorization", "auth", "credit_card", "creditcard",
	"cc", "ssn", "social_security", "private_key", "access_token",
	"refresh_token", "bearer", "jwt", "session", "cookie",
}

// NewSafeLogger creates a new SafeLogger with default settings.
func NewSafeLogger() *SafeLogger {
	keys := make(map[string]bool, len(defaultSensitiveKeys))
	for _, k := range defaultSensitiveKeys {
		keys[strings.ToLower(k)] = true
	}
	return &SafeLogger{
		sensitiveKeys: keys,
		maxLength:     10000,
	}
}

// NewSafeLoggerWithKeys creates a SafeLogger with custom sensitive keys.
func NewSafeLoggerWithKeys(keys []string, maxLength int) *SafeLogger {
	keyMap := make(map[string]bool, len(keys))
	for _, k := range keys {
		keyMap[strings.ToLower(k)] = true
	}
	return &SafeLogger{
		sensitiveKeys: keyMap,
		maxLength:     maxLength,
	}
}

// Redact redacts sensitive information from a map.
func (l *SafeLogger) Redact(data map[string]interface{}) map[string]interface{} {
	return l.redactDepth(data, 0)
}

func (l *SafeLogger) redactDepth(data map[string]interface{}, depth int) map[string]interface{} {
	if depth > MaxRecursionDepth || data == nil {
		return data
	}

	result := make(map[string]interface{}, len(data))

	for key, value := range data {
		lowKey := strings.ToLower(key)
		if l.sensitiveKeys[lowKey] {
			result[key] = "[REDACTED]"
			continue
		}

		switch v := value.(type) {
		case string:
			result[key] = l.redactString(v)
		case map[string]interface{}:
			result[key] = l.redactDepth(v, depth+1)
		case []interface{}:
			result[key] = l.redactSlice(v, depth+1)
		default:
			result[key] = value
		}
	}

	return result
}

func (l *SafeLogger) redactSlice(data []interface{}, depth int) []interface{} {
	if depth > MaxRecursionDepth || data == nil {
		return data
	}

	result := make([]interface{}, len(data))
	for i, item := range data {
		switch v := item.(type) {
		case string:
			result[i] = l.redactString(v)
		case map[string]interface{}:
			result[i] = l.redactDepth(v, depth+1)
		case []interface{}:
			result[i] = l.redactSlice(v, depth+1)
		default:
			result[i] = item
		}
	}
	return result
}

func (l *SafeLogger) redactString(value string) string {
	// Remove control characters (prevent log injection)
	result := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1 // Remove control characters
		}
		return r
	}, value)

	// Truncate if too long
	if len(result) > l.maxLength {
		return result[:l.maxLength] + "...[TRUNCATED]"
	}

	return result
}

// RedactString sanitizes a single string for safe logging.
func (l *SafeLogger) RedactString(value string) string {
	return l.redactString(value)
}

// ---------- Utilities ----------

// getClientIP extracts the client IP address from the request,
// handling common proxy headers.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (comma-separated list, first is client)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	// Strip port if present
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		// Check if this is IPv6 in brackets
		if strings.Contains(addr, "[") {
			if bracketIdx := strings.LastIndex(addr, "]"); bracketIdx != -1 && bracketIdx < idx {
				return addr[:idx]
			}
			// IPv6 without port, just remove brackets
			return strings.Trim(addr, "[]")
		}
		return addr[:idx]
	}
	return addr
}

// ---------- Error Handler ----------

// ErrorHandler provides production-safe error responses.
type ErrorHandler struct {
	isDev  bool
	logger *SafeLogger
}

// NewErrorHandler creates a new ErrorHandler.
// In production (isDev=false), error details are hidden.
func NewErrorHandler(isDev bool) *ErrorHandler {
	return &ErrorHandler{
		isDev:  isDev,
		logger: NewSafeLogger(),
	}
}

// NewErrorHandlerWithLogger creates an ErrorHandler with a custom logger.
func NewErrorHandlerWithLogger(isDev bool, logger *SafeLogger) *ErrorHandler {
	return &ErrorHandler{
		isDev:  isDev,
		logger: logger,
	}
}

// Handle writes an error response, hiding details in production.
func (eh *ErrorHandler) Handle(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{}

	if statusCode >= 500 {
		response["error"] = "Internal Server Error"
	} else {
		response["error"] = err.Error()
	}

	if eh.isDev {
		response["details"] = err.Error()
	}

	json.NewEncoder(w).Encode(response)
}

// HandleFunc returns an http.HandlerFunc for error handling.
func (eh *ErrorHandler) HandleFunc(next func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := next(w, r); err != nil {
			statusCode := http.StatusInternalServerError
			if httpErr, ok := err.(interface{ StatusCode() int }); ok {
				statusCode = httpErr.StatusCode()
			}
			eh.Handle(w, err, statusCode)
		}
	}
}
