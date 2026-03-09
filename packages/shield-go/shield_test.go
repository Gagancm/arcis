/*
Shield Go Test Suite
=====================

Tests aligned with TEST_VECTORS.json spec for cross-platform consistency.
Run with: go test -v ./...
*/
package shield

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// SANITIZE STRING TESTS (from TEST_VECTORS.json)
// ============================================================================

func TestSanitizeString_XSS(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)

	tests := []struct {
		name     string
		input    string
		notContains string
	}{
		{
			name:     "removes script tags",
			input:    "<script>alert('xss')</script>",
			notContains: "<script>",
		},
		{
			name:     "removes onerror handler",
			input:    `<img onerror="alert(1)" src="x">`,
			notContains: "onerror",
		},
		{
			name:     "removes javascript protocol",
			input:    "javascript:alert(1)",
			notContains: "javascript:",
		},
		{
			name:     "removes iframe tags",
			input:    `<iframe src="evil.com">`,
			notContains: "<iframe",
		},
		{
			name:     "removes data protocol",
			input:    "data:text/html,<script>alert(1)</script>",
			notContains: "data:",
		},
		{
			name:     "removes vbscript protocol",
			input:    "vbscript:msgbox(1)",
			notContains: "vbscript:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if strings.Contains(strings.ToLower(result), strings.ToLower(tt.notContains)) {
				t.Errorf("SanitizeString(%q) = %q, should not contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

func TestSanitizeString_XSS_EncodesHTML(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)
	result := sanitizer.SanitizeString("Hello <b>World</b>")

	if !strings.Contains(result, "&lt;") {
		t.Errorf("Expected HTML entities, got: %s", result)
	}
	if !strings.Contains(result, "&gt;") {
		t.Errorf("Expected HTML entities, got: %s", result)
	}
}

func TestSanitizeString_SQL(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, true, false, false, false)

	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{
			name:        "removes DROP TABLE",
			input:       "'; DROP TABLE users; --",
			notContains: "DROP",
		},
		{
			name:        "removes OR 1=1 pattern",
			input:       "1 OR 1=1",
			notContains: "OR 1",
		},
		{
			name:        "removes SELECT",
			input:       "SELECT * FROM users",
			notContains: "SELECT",
		},
		{
			name:        "removes DELETE",
			input:       "1; DELETE FROM users",
			notContains: "DELETE",
		},
		{
			name:        "removes SQL comments",
			input:       "admin'--",
			notContains: "--",
		},
		{
			name:        "removes UNION",
			input:       "1 /* comment */ UNION SELECT",
			notContains: "UNION",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if strings.Contains(strings.ToUpper(result), strings.ToUpper(tt.notContains)) {
				t.Errorf("SanitizeString(%q) = %q, should not contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

func TestSanitizeString_PathTraversal(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, false, true, false)

	tests := []struct {
		name        string
		input       string
		notContains string
	}{
		{
			name:        "removes unix path traversal",
			input:       "../../etc/passwd",
			notContains: "../",
		},
		{
			name:        "removes windows path traversal",
			input:       "..\\..\\windows\\system32",
			notContains: "..\\",
		},
		{
			name:        "removes URL-encoded traversal",
			input:       "%2e%2e%2f%2e%2e%2f",
			notContains: "%2e%2e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if strings.Contains(strings.ToLower(result), strings.ToLower(tt.notContains)) {
				t.Errorf("SanitizeString(%q) = %q, should not contain %q", tt.input, result, tt.notContains)
			}
		})
	}
}

func TestSanitizeString_SafeInputUnchanged(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, false, true, false)
	input := "file.txt"
	result := sanitizer.SanitizeString(input)

	if result != input {
		t.Errorf("Safe input should be unchanged, got: %s", result)
	}
}

// ============================================================================
// SANITIZE OBJECT TESTS (from TEST_VECTORS.json)
// ============================================================================

func TestSanitizeMap_PrototypePollution(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, true, true, true, true)

	tests := []struct {
		name        string
		input       map[string]interface{}
		blockedKey  string
		requiredKey string
	}{
		{
			name:        "blocks __proto__ key",
			input:       map[string]interface{}{"__proto__": map[string]interface{}{"admin": true}, "name": "test"},
			blockedKey:  "__proto__",
			requiredKey: "name",
		},
		{
			name:        "blocks constructor key",
			input:       map[string]interface{}{"constructor": map[string]interface{}{"prototype": map[string]interface{}{}}, "email": "test@test.com"},
			blockedKey:  "constructor",
			requiredKey: "email",
		},
		{
			name:        "blocks prototype key",
			input:       map[string]interface{}{"prototype": map[string]interface{}{"isAdmin": true}, "value": 123},
			blockedKey:  "prototype",
			requiredKey: "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeMap(tt.input)

			if _, exists := result[tt.blockedKey]; exists {
				t.Errorf("Result should not contain blocked key %q", tt.blockedKey)
			}
			if _, exists := result[tt.requiredKey]; !exists {
				t.Errorf("Result should contain required key %q", tt.requiredKey)
			}
		})
	}
}

func TestSanitizeMap_NoSQLInjection(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, true, false, false)

	tests := []struct {
		name        string
		input       map[string]interface{}
		blockedKeys []string
		requiredKey string
	}{
		{
			name:        "blocks $gt operator",
			input:       map[string]interface{}{"$gt": "", "name": "test"},
			blockedKeys: []string{"$gt"},
			requiredKey: "name",
		},
		{
			name:        "blocks $where operator",
			input:       map[string]interface{}{"$where": "function(){ return true; }", "id": 1},
			blockedKeys: []string{"$where"},
			requiredKey: "id",
		},
		{
			name:        "blocks multiple operators",
			input:       map[string]interface{}{"$ne": nil, "$or": []interface{}{}, "valid": true},
			blockedKeys: []string{"$ne", "$or"},
			requiredKey: "valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeMap(tt.input)

			for _, key := range tt.blockedKeys {
				if _, exists := result[key]; exists {
					t.Errorf("Result should not contain blocked key %q", key)
				}
			}
			if _, exists := result[tt.requiredKey]; !exists {
				t.Errorf("Result should contain required key %q", tt.requiredKey)
			}
		})
	}
}

// TEST_VECTORS: nested objects with $ keys should also be checked
func TestSanitizeMap_NoSQLInjection_NestedRegex(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(false, false, true, false, false)

	input := map[string]interface{}{
		"username": map[string]interface{}{"$regex": ".*"},
		"password": "test",
	}
	result := sanitizer.SanitizeMap(input)

	// The nested $regex should be blocked
	if username, exists := result["username"]; exists {
		if usernameMap, ok := username.(map[string]interface{}); ok {
			if _, hasRegex := usernameMap["$regex"]; hasRegex {
				t.Error("Nested $regex operator should be blocked")
			}
		}
	}

	// password should still be present
	if _, exists := result["password"]; !exists {
		t.Error("password key should still be present")
	}
}

func TestSanitizeMap_NestedObjects(t *testing.T) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)

	t.Run("sanitizes nested strings", func(t *testing.T) {
		input := map[string]interface{}{
			"user": map[string]interface{}{
				"name": "<script>xss</script>",
			},
		}
		result := sanitizer.SanitizeMap(input)

		user := result["user"].(map[string]interface{})
		if strings.Contains(user["name"].(string), "<script>") {
			t.Error("Nested string should be sanitized")
		}
	})

	t.Run("sanitizes array items", func(t *testing.T) {
		input := map[string]interface{}{
			"items": []interface{}{"<script>alert(1)</script>", "normal"},
		}
		result := sanitizer.SanitizeMap(input)

		items := result["items"].([]interface{})
		if strings.Contains(items[0].(string), "<script>") {
			t.Error("Array items should be sanitized")
		}
		if items[1].(string) != "normal" {
			t.Error("Normal items should be unchanged")
		}
	})
}

// ============================================================================
// RATE LIMITER TESTS (from TEST_VECTORS.json)
// ============================================================================

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	defer rl.Close()

	for i := 0; i < 3; i++ {
		result := rl.CheckKey("test-ip")
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_ReturnsHeaders(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	defer rl.Close()

	result := rl.CheckKey("test-ip")

	if result.Limit != 100 {
		t.Errorf("Expected limit 100, got %d", result.Limit)
	}
	if result.Remaining != 99 {
		t.Errorf("Expected remaining 99, got %d", result.Remaining)
	}
	if result.Reset <= 0 {
		t.Errorf("Expected positive reset time, got %v", result.Reset)
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	defer rl.Close()

	// Make 3 requests (all should pass)
	for i := 0; i < 3; i++ {
		result := rl.CheckKey("192.168.1.1")
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 4th request should be blocked
	result := rl.CheckKey("192.168.1.1")
	if result.Allowed {
		t.Error("4th request should be blocked")
	}
}

func TestRateLimiter_DifferentIPsSeparateLimits(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	defer rl.Close()

	// 3 different IPs, 2 requests each - all should pass
	for ip := 0; ip < 3; ip++ {
		key := "192.168.1." + string(rune('0'+ip))
		for i := 0; i < 2; i++ {
			result := rl.CheckKey(key)
			if !result.Allowed {
				t.Errorf("Request from %s should be allowed", key)
			}
		}
	}
}

func TestRateLimiter_SkipFunction(t *testing.T) {
	config := DefaultConfig()
	config.RateLimitMax = 1
	config.RateLimitSkip = func(r *http.Request) bool {
		return true // Skip all
	}

	s := NewWithConfig(config)
	defer s.Close()

	// Make multiple requests - all should pass due to skip
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		result := s.rateLimiter.Check(req)
		if !result.Allowed {
			t.Errorf("Request %d should be allowed (skipped)", i+1)
		}
	}
}

// ============================================================================
// SECURITY HEADERS TESTS (from TEST_VECTORS.json)
// ============================================================================

func TestSecurityHeaders_DefaultHeaders(t *testing.T) {
	config := DefaultConfig()
	headers := NewSecurityHeaders(config)
	h := headers.GetHeaders()

	requiredHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
	}

	for header, expected := range requiredHeaders {
		if h[header] != expected {
			t.Errorf("Expected %s: %s, got: %s", header, expected, h[header])
		}
	}

	// CSP should be set
	if _, exists := h["Content-Security-Policy"]; !exists {
		t.Error("Content-Security-Policy should be set")
	}

	// HSTS should contain max-age
	if hsts, exists := h["Strict-Transport-Security"]; !exists || !strings.Contains(hsts, "max-age=") {
		t.Error("Strict-Transport-Security should contain max-age=")
	}
}

func TestSecurityHeaders_CustomCSP(t *testing.T) {
	config := DefaultConfig()
	config.CSP = "default-src 'none'"
	headers := NewSecurityHeaders(config)

	h := headers.GetHeaders()
	if h["Content-Security-Policy"] != "default-src 'none'" {
		t.Errorf("Expected custom CSP, got: %s", h["Content-Security-Policy"])
	}
}

// ============================================================================
// VALIDATOR TESTS (from TEST_VECTORS.json)
// ============================================================================

func TestValidator_RequiredField(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{})
	if err == nil {
		t.Error("Should fail when required field is missing")
	}
	if err != nil && !containsString(err.Errors, "required") {
		t.Errorf("Error should mention 'required', got: %v", err.Errors)
	}
}

func TestValidator_EmailInvalid(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"email": "invalid"})
	if err == nil {
		t.Error("Should fail for invalid email")
	}
}

func TestValidator_EmailValid(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	validated, err := validator.Validate(map[string]interface{}{"email": "test@example.com"})
	if err != nil {
		t.Errorf("Valid email should pass: %v", err)
	}
	if validated["email"] == nil {
		t.Error("Validated data should contain email")
	}
}

func TestValidator_StringLengthTooShort(t *testing.T) {
	minLen := float64(3)
	schema := ValidationSchema{
		"name": {Type: "string", Min: &minLen},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"name": "ab"})
	if err == nil {
		t.Error("Should fail when string is too short")
	}
	if err != nil && !containsString(err.Errors, "at least 3") {
		t.Errorf("Error should mention 'at least 3', got: %v", err.Errors)
	}
}

func TestValidator_StringLengthTooLong(t *testing.T) {
	minLen := float64(3)
	maxLen := float64(10)
	schema := ValidationSchema{
		"name": {Type: "string", Min: &minLen, Max: &maxLen},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"name": "this is way too long"})
	if err == nil {
		t.Error("Should fail when string is too long")
	}
	if err != nil && !containsString(err.Errors, "at most 10") {
		t.Errorf("Error should mention 'at most 10', got: %v", err.Errors)
	}
}

func TestValidator_NumberBelowMin(t *testing.T) {
	minVal := float64(0)
	schema := ValidationSchema{
		"age": {Type: "number", Min: &minVal},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"age": -5})
	if err == nil {
		t.Error("Should fail when number is below min")
	}
	if err != nil && !containsString(err.Errors, "at least 0") {
		t.Errorf("Error should mention 'at least 0', got: %v", err.Errors)
	}
}

func TestValidator_NumberAboveMax(t *testing.T) {
	maxVal := float64(150)
	schema := ValidationSchema{
		"age": {Type: "number", Max: &maxVal},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"age": 200})
	if err == nil {
		t.Error("Should fail when number is above max")
	}
	if err != nil && !containsString(err.Errors, "at most 150") {
		t.Errorf("Error should mention 'at most 150', got: %v", err.Errors)
	}
}

func TestValidator_EnumInvalid(t *testing.T) {
	schema := ValidationSchema{
		"role": {Type: "string", Enum: []string{"user", "admin"}},
	}
	validator := NewValidator(schema)

	_, err := validator.Validate(map[string]interface{}{"role": "superadmin"})
	if err == nil {
		t.Error("Should fail for invalid enum value")
	}
	if err != nil && !containsString(err.Errors, "one of") {
		t.Errorf("Error should mention 'one of', got: %v", err.Errors)
	}
}

func TestValidator_EnumValid(t *testing.T) {
	schema := ValidationSchema{
		"role": {Type: "string", Enum: []string{"user", "admin"}},
	}
	validator := NewValidator(schema)

	validated, err := validator.Validate(map[string]interface{}{"role": "admin"})
	if err != nil {
		t.Errorf("Valid enum value should pass: %v", err)
	}
	if validated["role"] != "admin" {
		t.Error("Validated data should contain role")
	}
}

func TestValidator_MassAssignmentPrevention(t *testing.T) {
	schema := ValidationSchema{
		"email": {Type: "email", Required: true},
	}
	validator := NewValidator(schema)

	validated, err := validator.Validate(map[string]interface{}{
		"email":   "test@test.com",
		"isAdmin": true,
		"role":    "admin",
	})
	if err != nil {
		t.Errorf("Should pass validation: %v", err)
	}

	// email should be present
	if validated["email"] == nil {
		t.Error("email should be in validated output")
	}

	// isAdmin and role should NOT be present (mass assignment prevention)
	if _, exists := validated["isAdmin"]; exists {
		t.Error("isAdmin should NOT be in validated output")
	}
	if _, exists := validated["role"]; exists {
		t.Error("role should NOT be in validated output")
	}
}

// Helper function to check if any error contains a substring
func containsString(errors []string, substr string) bool {
	for _, e := range errors {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}

// ============================================================================
// SAFE LOGGER TESTS (from TEST_VECTORS.json)
// ============================================================================

func TestSafeLogger_RedactsSensitiveKeys(t *testing.T) {
	logger := NewSafeLogger()

	data := map[string]interface{}{
		"email":    "test@test.com",
		"password": "secret123",
	}
	redacted := logger.Redact(data)

	if redacted["password"] != "[REDACTED]" {
		t.Error("Password should be redacted")
	}
	if redacted["email"] != "test@test.com" {
		t.Error("Email should not be redacted")
	}
}

func TestSafeLogger_RedactsMultipleKeys(t *testing.T) {
	logger := NewSafeLogger()

	data := map[string]interface{}{
		"user":  "john",
		"token": "abc123",
	}
	redacted := logger.Redact(data)

	if redacted["token"] != "[REDACTED]" {
		t.Error("Token should be redacted")
	}
	if redacted["user"] != "john" {
		t.Error("User should not be redacted")
	}
}

func TestSafeLogger_RemovesLogInjection(t *testing.T) {
	logger := NewSafeLogger()

	tests := []struct {
		name     string
		input    string
		notContains string
	}{
		{
			name:        "removes newlines",
			input:       "User: attacker\nAdmin logged in: true",
			notContains: "\n",
		},
		{
			name:        "removes carriage returns",
			input:       "Normal log\r\nFake entry",
			notContains: "\r",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := logger.RedactString(tt.input)
			if strings.Contains(result, tt.notContains) {
				t.Errorf("Result should not contain %q", tt.notContains)
			}
		})
	}
}

func TestSafeLogger_Truncates(t *testing.T) {
	logger := NewSafeLoggerWithKeys(nil, 50)

	longMessage := strings.Repeat("a", 100)
	truncated := logger.RedactString(longMessage)

	if len(truncated) >= 100 {
		t.Error("Message should be truncated")
	}
	if !strings.Contains(truncated, "[TRUNCATED]") {
		t.Error("Message should contain [TRUNCATED] marker")
	}
}

// ============================================================================
// MIDDLEWARE INTEGRATION TESTS
// ============================================================================

func TestMiddleware_SetsSecurityHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s := New()
	defer s.Close()

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	s.Handler(handler).ServeHTTP(rec, req)

	// Check security headers
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be set")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be set")
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy should be set")
	}
}

func TestMiddleware_SetsRateLimitHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultConfig()
	config.RateLimitMax = 100
	s := NewWithConfig(config)
	defer s.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	s.Handler(handler).ServeHTTP(rec, req)

	if rec.Header().Get("X-RateLimit-Limit") != "100" {
		t.Errorf("X-RateLimit-Limit should be 100, got: %s", rec.Header().Get("X-RateLimit-Limit"))
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("X-RateLimit-Remaining should be set")
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("X-RateLimit-Reset should be set")
	}
}

func TestMiddleware_BlocksRateLimitExceeded(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultConfig()
	config.RateLimitMax = 2
	s := NewWithConfig(config)
	defer s.Close()

	// Make 2 requests (should pass)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()
		s.Handler(handler).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d should return 200", i+1)
		}
	}

	// 3rd request should be blocked
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	s.Handler(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request should return 429, got: %d", rec.Code)
	}

	// Check response body
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to parse response body: %v", err)
	}
	if _, exists := body["error"]; !exists {
		t.Error("Response should contain error message")
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Response should have Retry-After header")
	}
}

func TestMiddleware_RemovesFingerprintHeaders(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.WriteHeader(http.StatusOK)
	})

	s := New()
	defer s.Close()

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	s.Handler(handler).ServeHTTP(rec, req)

	// These headers should be removed
	if rec.Header().Get("Server") != "" {
		t.Error("Server header should be removed")
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Error("X-Powered-By header should be removed")
	}
}

// ============================================================================
// ERROR HANDLER TESTS
// ============================================================================

func TestErrorHandler_HidesDetailsInProduction(t *testing.T) {
	eh := NewErrorHandler(false)

	rec := httptest.NewRecorder()
	err := &testError{msg: "Database connection failed"}

	eh.Handle(rec, err, http.StatusInternalServerError)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if body["error"] != "Internal Server Error" {
		t.Error("Should show generic error in production")
	}
	if _, exists := body["details"]; exists {
		t.Error("Should not expose details in production")
	}
}

func TestErrorHandler_ShowsDetailsInDev(t *testing.T) {
	eh := NewErrorHandler(true)

	rec := httptest.NewRecorder()
	err := &testError{msg: "Something broke"}

	eh.Handle(rec, err, http.StatusInternalServerError)

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if body["details"] != "Something broke" {
		t.Error("Should show details in dev mode")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

// ============================================================================
// UTILITY TESTS
// ============================================================================

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		expected   string
	}{
		{
			name:       "uses RemoteAddr",
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "prefers X-Forwarded-For",
			remoteAddr: "127.0.0.1:12345",
			xff:        "10.0.0.1, 192.168.1.1",
			expected:   "10.0.0.1",
		},
		{
			name:       "uses X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			xri:        "10.0.0.2",
			expected:   "10.0.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			result := getClientIP(req)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// ============================================================================
// BENCHMARK TESTS
// ============================================================================

func BenchmarkSanitizeString_XSS(b *testing.B) {
	sanitizer := NewSanitizerWithOptions(true, false, false, false, false)
	input := "<script>alert('xss')</script>"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizer.SanitizeString(input)
	}
}

func BenchmarkSanitizeMap_Nested(b *testing.B) {
	sanitizer := NewSanitizerWithOptions(true, true, true, true, true)
	input := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "<script>xss</script>",
			"email": "test@test.com",
			"items": []interface{}{"<script>1</script>", "normal"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sanitizer.SanitizeMap(input)
	}
}

func BenchmarkRateLimiter_Check(b *testing.B) {
	rl := NewRateLimiter(100000, time.Minute)
	defer rl.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.CheckKey("test-ip")
	}
}
