# Audit State — Go (`arcis-go`)

**Status:** 🟠 NOT STARTED — known issues pre-populated from `arcis-audit-report.md`
**Last audited:** not yet (issues below are from the cross-SDK report, not a full checklist pass)
**Test count:** unknown
**Package path:** `packages/arcis-go`

---

## Checklist Results

> Most items are PENDING — a full triage pass has not been done yet. Known issues from the cross-SDK audit are pre-populated as findings.

### CAT-1: Spec Compliance
- [ ] Every function in `spec/API_SPEC.md` exists and is exported — **PENDING**
- [ ] Every config option in spec is wired up with correct default — **PENDING**
- [ ] All `spec/TEST_VECTORS.json` cases are exercised in tests — **PENDING**

### CAT-2: Pattern Coverage
- [x] All patterns in `packages/core/patterns.json` are implemented — **FAIL** → FIND-1
- [ ] ReDoS-safe variants used where `redos_safe: false` — **PASS** (Go hardcodes `pattern_safe` for script tag)
- [ ] No local duplicate pattern list — **PENDING**

### CAT-3: Security Logic
- [ ] Sanitization: remove before encode — **PENDING**
- [ ] Reject mode: returns error, does not pass partial input — **PENDING**
- [ ] Prototype pollution keys blocked at traversal — **PENDING**
- [ ] NoSQL operators: all keys blocked — **PENDING**
- [ ] Redis store: timestamps in consistent units — **PENDING** (no Redis store in Go SDK; N/A if confirmed)
- [ ] Rate limiter: per-key isolation — **PENDING**

### CAT-4: Resource Management
- [ ] Background intervals/goroutines have shutdown path — **PENDING**
- [x] Cleanup interval not created when external store provided — **PASS** (confirmed in cross-SDK table)
- [ ] Store constructors validate bounds — **PENDING**

### CAT-5: Type Safety
- [ ] No untyped casts in public API paths — **PENDING**
- [ ] Custom validator return types don't silently accept zero values — **PENDING**
- [ ] Store interface return types consistent — **PENDING**

### CAT-6: Test Quality
- [ ] Prototype pollution test creates real own-key — **PENDING**
- [ ] Fake timer / mock cleanup in `finally`/defer — **PENDING**
- [ ] Test server lifecycle guarded — **PENDING**
- [ ] Threat collection tests assert `.original` and `.pattern` — **PENDING**
- [ ] Test helpers use actual constants — **PENDING**

### CAT-7: Cross-SDK Consistency

| Feature | Go | Node.js baseline | Match? |
|---------|----|-----------------|--------|
| SLEEP/BENCHMARK SQL patterns | ❌ Missing | ✅ | No — FIND-1 |
| Script tag ReDoS-safe | ✅ | ✅ | Yes |
| SafeLogger extends defaults | ❌ Replaces | ✅ | No — FIND-2 |
| Redis timestamps in ms | N/A | N/A | — |
| Cleanup interval skipped for ext. store | ✅ | ✅ | Yes |
| Magic numbers → named constants | ❌ `1000000` bare | ✅ | No — FIND-3 |
| Body exhaustion documented | ❌ Missing | N/A | — FIND-4 |
| `data:` false positive scope | ⚠️ Same | ⚠️ | — FIND-5 |

### CAT-8: Dead Code / Hygiene
- [ ] No unused imports or exports — **PENDING**
- [x] No magic numbers — **FAIL** → FIND-3
- [ ] No hardcoded fallback patterns diverging from `patterns.json` — **PENDING**

---

## Findings

---

### FIND-1: SLEEP/BENCHMARK SQL patterns missing in Go
- **Category:** CAT-2, CAT-7
- **Severity:** P1
- **File:** `packages/arcis-go/arcis.go` line 266–274
- **What:** `patterns.json` defines `sqli-sleep` (`\bSLEEP\s*\(\s*\d+\s*\)`) and `sqli-benchmark` (`\bBENCHMARK\s*\(`). Go's `sqlPatterns` slice does not include these. `SLEEP(5)` and `BENCHMARK(100000, MD5(1))` pass through unblocked.
- **Why:** Time-based blind SQL injection is a primary technique for data exfiltration from databases that return no error messages.
- **Fix:**
  ```go
  // Add to sqlPatterns:
  regexp.MustCompile(`(?i)\bSLEEP\s*\(\s*\d+\s*\)`),
  regexp.MustCompile(`(?i)\bBENCHMARK\s*\(`),
  ```
- **Decision:** fix
- **Status:** open

---

### FIND-2: `NewSafeLoggerWithKeys` replaces defaults instead of extending them
- **Category:** CAT-3, CAT-7
- **Severity:** P1
- **File:** `packages/arcis-go/arcis.go` line 1144–1154
- **What:**
  ```go
  func NewSafeLoggerWithKeys(keys []string, maxLength int) *SafeLogger {
      keyMap := make(map[string]bool, len(keys))
      for _, k := range keys {
          keyMap[strings.ToLower(k)] = true  // only custom keys — defaults NOT included
      }
      return &SafeLogger{sensitiveKeys: keyMap, maxLength: maxLength}
  }
  ```
  A caller passing `[]string{"my_secret"}` gets a logger that logs `password`, `token`, `apiKey`, `authorization`, `jwt` in plaintext.
- **Why:** Silent security regression. Developer expects to ADD a custom key on top of defaults — instead they replace the entire set.
- **Fix:**
  ```go
  func NewSafeLoggerWithKeys(keys []string, maxLength int) *SafeLogger {
      keyMap := make(map[string]bool, len(defaultSensitiveKeys)+len(keys))
      for _, k := range defaultSensitiveKeys {
          keyMap[k] = true
      }
      for _, k := range keys {
          keyMap[strings.ToLower(k)] = true
      }
      return &SafeLogger{sensitiveKeys: keyMap, maxLength: maxLength}
  }
  ```
- **Decision:** fix
- **Status:** open

---

### FIND-3: Magic number `1000000` not a named constant
- **Category:** CAT-8
- **Severity:** P2
- **File:** `packages/arcis-go/arcis.go` lines 103, 336, 357
- **What:** `1000000` appears three times (in `DefaultConfig()`, `NewSanitizer()`, `NewSanitizerWithOptions()`). Node.js and Python both define `DEFAULT_MAX_INPUT_SIZE = 1_000_000`.
- **Why:** If the default changes, three sites must be updated. Risk of drift.
- **Fix:** Define `const DefaultMaxInputSize = 1_000_000` and replace all three uses.
- **Decision:** fix (trivial)
- **Status:** open

---

### FIND-4: `SanitizeBody()` and `ValidateHandler` body exhaustion not documented
- **Category:** CAT-8
- **Severity:** P2
- **File:** `packages/arcis-go/arcis.go` lines 232, 1056
- **What:** Both functions read `r.Body` and exhaust the stream. Handlers that call `r.Body` again get EOF. No doc comment warns of this.
- **Why:** Silent bugs for users who try to read the body again.
- **Fix:** Add doc comment to each:
  - `SanitizeBody`: `// Note: reads and exhausts r.Body. Access sanitized data via context, not r.Body.`
  - `ValidateHandler`: `// After this middleware runs, read request body via GetValidatedBody(r), not r.Body.`
- **Decision:** fix (trivial)
- **Status:** open

---

### FIND-5: `data:` XSS pattern causes false positives (cross-SDK)
- **Category:** CAT-3
- **Severity:** P2
- **File:** `packages/arcis-go/arcis.go` line 260
- **What:** `(?i)data:` matches anywhere, including `"metadata: value"` and `"stored data: 42"`. Legitimate strings silently corrupted.
- **Why:** False positive data corruption on valid API inputs.
- **Fix:** Tighten to `(?:^|[\s"'=])data:` or match specific dangerous MIME types.
- **Decision:** defer (cross-SDK issue; fix coordinated with Python and Node.js)
- **Status:** deferred

---

### FIND-6: `activeInstances` slice not mutex-protected in Gin and Echo adapters
- **Category:** CAT-4
- **Severity:** P3
- **File:** `packages/arcis-go/gin/gin.go` line 150, `packages/arcis-go/echo/echo.go` line 157
- **What:**
  ```go
  var activeInstances []*arcisInstance
  activeInstances = append(activeInstances, instance)  // no lock
  ```
  Concurrent calls to setup functions race on this slice. In practice setup runs in `main()` before `ListenAndServe`, so unlikely to trigger — but `go test -race` would flag it.
- **Why:** Data race flag in race detector; not a real-world concern given typical usage.
- **Fix:** Protect with `sync.Mutex`.
- **Decision:** fix if test -race is part of CI; otherwise defer
- **Status:** open

---

## Decisions Log

| FIND | Decision | Reason |
|------|----------|--------|
| FIND-5 | defer | Cross-SDK issue; fix coordinated across all SDKs |

---

## Sign-Off

Not signed off. Complete triage (all PENDING items) then Fix phase first.
