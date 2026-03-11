# Audit State — Python (`arcis-python`)

**Status:** ✅ COMPLETE — all findings resolved
**Last audited:** 2026-03-10
**Auditor:** Claude Opus 4.6 (structured checklist audit)
**Test count at sign-off:** 240 passed, 1 skipped, 0 warnings
**Package path:** `packages/arcis-python`

---

## Previous Audit (resolved)

All 23 findings from the prior audit (FIND-1 through FIND-9, NEW-1 through NEW-14) were resolved in the previous session. This is a fresh pass using the 8-category structured checklist from `AUDIT_SYSTEM.md`.

---

## CAT-1: Spec Compliance

- [x] Every function in `spec/API_SPEC.md` exists and is exported — **PASS**
  - `sanitize_string`, `sanitize_object` (as `sanitize_dict`), `create_sanitizer` (as `Arcis`/middleware)
  - `create_rate_limiter` → `RateLimiter` + `AsyncRateLimiter`
  - `create_headers` → `SecurityHeaders`
  - `validate` → `SchemaValidator.validate` + `create_validator`
  - `create_logger` → `SafeLogger`
  - `create_error_handler` → `ErrorHandler` + `create_error_handler`
  - All exported in `__init__.py` `__all__`

- [x] Every config option in spec is wired up with correct default — **PASS**
  - `max=100`, `windowMs=60000`, `message` matches spec
  - `xss/sql/nosql/path/proto` all default `True`
  - Headers: CSP, X-Frame-Options=DENY, nosniff, HSTS all match
  - Logger: `maxLength=10000`, sensitive keys loaded from PATTERNS
  - Validator: `sanitize=True` default, `required=False` default

- [x] All `spec/TEST_VECTORS.json` cases are exercised in tests — **PASS** (46 conformance tests)

---

## CAT-2: Pattern Coverage

- [x] All patterns in `packages/core/patterns.json` are implemented — **PASS** (with caveat → FIND-2)
  - XSS: 10/10 patterns loaded from PATTERNS (prefers `pattern_safe`)
  - SQL: 9/9 patterns loaded from PATTERNS
  - NoSQL: 16/16 dangerous_keys loaded from PATTERNS
  - Path traversal: 5/5 patterns loaded from PATTERNS
  - Prototype pollution: 3/3 keys loaded from PATTERNS (with hardcoded fallback)

- [x] ReDoS-safe variants used where `redos_safe: false` — **PASS**
  - `sanitize.py:47`: `rule.get("pattern_safe") or rule.get("pattern")`

- [x] No pattern list defined locally that duplicates/diverges from core — **PASS** (all loaded from PATTERNS)

---

## CAT-3: Security Logic

- [x] Sanitization: remove before encode — **PASS**
  - `sanitize.py:98-106`: remove XSS patterns FIRST, then encode remaining

- [x] Reject mode: returns error, does not pass partial input — **PASS**
  - Rate limiter raises `RateLimitExceeded`; middleware returns 429 before handler
  - Validator returns errors list, only validated fields in output

- [x] Prototype pollution keys blocked at object traversal level — **PASS**
  - `sanitize.py:140-141`: `if key.lower() in self._proto_keys: continue`

- [x] NoSQL operators: all keys blocked — **PASS**
  - `sanitize.py:144`: `if self.nosql and key.lower() in self._nosql_keys: continue`
  - Case-insensitive via `.lower()`

- [x] Redis store: timestamps in consistent units (ms everywhere) — **PASS**
  - `redis.py`: stores in ms, converts sec→ms on set, ms→sec on get
  - Lua script operates in ms internally

- [x] Rate limiter: per-key isolation — **PASS**
  - Each key gets its own `RateLimitEntry` in store

---

## CAT-4: Resource Management

- [x] Every background thread/task has a documented shutdown path — **PASS**
  - Sync: `RateLimiter.close()` sets event, joins thread
  - Async: `AsyncRateLimiter.close()` cancels task
  - `atexit.register(self.close)` in sync limiter

- [x] Cleanup interval not created when external store is provided — **PASS** (both sync and async skip)

- [x] Store constructors validate bounds — **PASS**
  - Both sync and async: `ValueError` on `max_requests < 1` or `window_ms < 1`

---

## CAT-5: Type Safety

- [x] No `any` casts in public API paths — **PASS**
  - Python doesn't have `any` casts, but no `# type: ignore` on public APIs

- [x] Custom validator / callback return types don't silently accept None — **PASS**
  - `schema.py:152-153`: `if custom_result is not True:` — rejects None, False, strings

- [x] Store interface return types consistent — **PASS** (all stores return `Optional[RateLimitEntry]`)

---

## CAT-6: Test Quality

- [x] Conformance tests exercise TEST_VECTORS.json — **PASS** (46 tests)

- [x] Fake timer / mock cleanup in `finally` block — **PASS** (N/A — Python tests don't use fake timers)

- [x] Test server lifecycle guarded — **PASS**
  - Flask tests use `pytest.fixture` with `app.test_client()`

- [x] Threat collection tests — **PASS** (N/A — Python SDK doesn't have a threat collection API)

- [x] Test helpers use actual constants — **PASS** (no test helpers that hardcode subsets)

---

## CAT-7: Cross-SDK Consistency

| Feature | Python | Node.js | Match? |
|---------|--------|---------|--------|
| SLEEP/BENCHMARK SQL patterns | ✅ embedded + patterns.json | ✅ | ✅ |
| Script tag ReDoS-safe | ✅ `pattern_safe` or `pattern` | ✅ | ✅ |
| SafeLogger extends defaults | ✅ merges with `SENSITIVE_KEYS` | ✅ | ✅ |
| Redis timestamps in ms | ✅ | N/A | ✅ |
| Cleanup interval skipped for external store | ✅ | ✅ | ✅ |
| Magic numbers → named constants | ✅ | ✅ | ✅ |
| Feature names match spec | ✅ | ✅ | ✅ |
| Return types match spec | ✅ | ✅ | ✅ |
| Default values match spec | ✅ | ✅ | ✅ |

---

## CAT-8: Dead Code / Hygiene

- [x] No unused imports or exports — **PASS**

- [x] No magic numbers — **PASS** (all extracted to `core/constants.py`)

- [x] No hardcoded fallback patterns diverging from core — **PASS** (all loaded from PATTERNS)

---

## Findings

---

### FIND-1: Conformance tests are an empty placeholder — TEST_VECTORS.json not exercised

- **Category:** CAT-1, CAT-6
- **Severity:** P1
- **File:** `tests/conformance/test_conformance.py`
- **What:** File contains only a one-line docstring. None of the 30+ test cases in `spec/TEST_VECTORS.json` are automated. The XSS test vectors expect `&lt;` encoding in output, but the current sanitizer removes entire tags leaving nothing to encode — the test vectors and the implementation have diverged.
- **Why:** No automated way to verify cross-SDK behavioral consistency. Regressions in sanitization output won't be caught.
- **Fix:** Either (a) implement conformance tests that load TEST_VECTORS.json and run each case, updating the expected outputs to match the "remove before encode" architecture, or (b) update TEST_VECTORS.json to match current behavior.
- **Decision:** fix
- **Status:** ✅ done

---

### FIND-2: Command injection patterns hardcoded — diverge from patterns.json

- **Category:** CAT-2, CAT-8
- **Severity:** P1
- **File:** `sanitizers/sanitize.py:76-80`
- **What:** Command injection patterns are hardcoded inline:
  ```python
  self._command_patterns = [
      re.compile(r'[;&|`$()]'),
      re.compile(r'\b(cat|ls|rm|mv|cp|wget|curl|nc|bash|sh|python|perl|ruby|php)\b', re.IGNORECASE),
  ]
  ```
  `patterns.json` defines 3 rules for command injection (`cmdi-shell-chars`, `cmdi-commands`, `cmdi-redirection`). The Python SDK:
  1. Only has 2 of 3 patterns — **missing `cmdi-redirection`** (`(>>|<<|>|<)\s*[/\w]`)
  2. The `cmdi-commands` pattern is missing `node`, `powershell`, `cmd` which are in `patterns.json`
  3. Does not load from PATTERNS like XSS/SQL/path do — violates single-source-of-truth
- **Why:** Shell redirection attacks (`echo malicious > /etc/passwd`) bypass the filter. Missing commands (`node`, `powershell`, `cmd`) are not caught.
- **Fix:** Load command injection patterns from `PATTERNS["patterns"]["command_injection"]["rules"]` like the other categories. Remove hardcoded patterns.
- **Decision:** fix
- **Status:** ✅ done

---

### FIND-3: Sync RateLimiter always starts cleanup thread — even with external store

- **Category:** CAT-4, CAT-7
- **Severity:** P2
- **File:** `middleware/rate_limit.py:57-60`
- **What:** `_start_cleanup_thread()` is called unconditionally in `__init__`. When a Redis store is provided, the cleanup thread calls `store.cleanup()` every `window_seconds`, but Redis cleanup is a no-op. The thread still runs, consuming a system thread.

  The async version (`AsyncRateLimiter`) correctly checks `self._store_provided` and skips cleanup.
- **Why:** Wastes a thread per RateLimiter instance. In deployments with many rate limiters (per-route limiting), this adds up. Inconsistent with async behavior.
- **Fix:** Track `_store_provided = store is not None` and skip `_start_cleanup_thread()` if True:
  ```python
  self._store_provided = store is not None
  self.store = store or InMemoryStore()
  if not self._store_provided:
      self._start_cleanup_thread()
  ```
- **Decision:** fix
- **Status:** ✅ done

---

### FIND-4: Redis store `get()` returns Dict, sync store returns RateLimitEntry — type mismatch

- **Category:** CAT-5, CAT-7
- **Severity:** P1
- **File:** `stores/redis.py:129` vs `stores/memory.py:21`
- **What:** `InMemoryStore.get()` returns `Optional[RateLimitEntry]` (dataclass with `.count` and `.reset_time` attributes). `RedisRateLimitStore.get()` returns `Optional[Dict[str, Any]]` (dict with `["count"]` and `["reset_time"]` keys).

  `RateLimiter.check()` at line 147 does `entry.reset_time` — this works with `InMemoryStore` but would crash with `RedisRateLimitStore` because dicts don't have attribute access.
- **Why:** Redis store is not actually usable with the sync `RateLimiter` despite being documented as compatible. Plugging in a Redis store will raise `AttributeError: 'dict' object has no attribute 'reset_time'`.
- **Fix:** Make `RedisRateLimitStore.get()` return `RateLimitEntry` instead of a dict:
  ```python
  return RateLimitEntry(count=int(count_raw), reset_time=reset_time_ms / 1000)
  ```
  Same for `AsyncRedisRateLimitStore.get()`.
- **Decision:** fix
- **Status:** ✅ done

---

### FIND-5: Magic numbers in multiple files

- **Category:** CAT-8, CAT-7
- **Severity:** P2
- **File:** Multiple locations
- **What:**
  - `headers.py:30`: `hsts_max_age: int = 31536000` — should be `HSTS_DEFAULT_MAX_AGE`
  - `safe_logger.py:31`: `max_length: int = 10000` — should be `DEFAULT_LOG_MAX_LENGTH`
  - `rate_limit.py:39`: `"Too many requests, please try again later."` — should be `DEFAULT_RATE_LIMIT_MESSAGE`
  - `rate_limit.py:36-37`: `max_requests=100`, `window_ms=60000` — should reference `DEFAULT_MAX_REQUESTS`, `DEFAULT_WINDOW_MS` from patterns.json
  - `fastapi.py:213`: `print(f"[Arcis Async Rate Limiter] Cleanup error: {e}")` — uses `print()` instead of `logging`
- **Why:** Inconsistent with Node.js which uses named constants. Hard to find and update defaults.
- **Fix:** Define constants in `core/constants.py` and reference them. Replace `print()` with `logger.error()`.
- **Decision:** fix (trivial)
- **Status:** ✅ done

---

### FIND-6: Async `check()` fail-open and skip paths missing `reset` key

- **Category:** CAT-3
- **Severity:** P2
- **File:** `fastapi.py:232-233` and `fastapi.py:244-245`
- **What:** When `_closed=True` or `skip_func` returns True, the async `check()` returns:
  ```python
  return {"allowed": True, "limit": self.max_requests, "remaining": self.max_requests}
  ```
  Missing `"reset"` key. The sync version was just fixed to include `"reset": 0`, but the async version still omits it.

  `ArcisMiddleware.dispatch()` at line 460 accesses `info.get('reset', 0)` so it won't crash, but consumers of the raw dict might.
- **Why:** Inconsistency between sync and async return shapes. External consumers of `check()` expecting `reset` key will get `KeyError`.
- **Fix:** Add `"reset": 0` to both paths, matching the sync fix.
- **Decision:** fix
- **Status:** ✅ done

---

### FIND-7: `datetime.utcnow()` deprecated — scheduled for removal

- **Category:** CAT-8
- **Severity:** P2
- **File:** `logging/safe_logger.py:72`
- **What:** `datetime.datetime.utcnow()` is deprecated since Python 3.12 and scheduled for removal. Already producing `DeprecationWarning` in test output.
- **Fix:** Replace with `datetime.datetime.now(datetime.UTC).isoformat() + "Z"` or `datetime.datetime.now(datetime.timezone.utc)`.
- **Decision:** fix (trivial)
- **Status:** ✅ done

---

### FIND-8: No command injection tests

- **Category:** CAT-6
- **Severity:** P2
- **File:** `tests/sanitizers/test_sanitize.py`
- **What:** There are test classes for XSS, SQL, path traversal, NoSQL, prototype pollution — but zero tests for command injection sanitization despite it being enabled by default.
- **Why:** No coverage for `Sanitizer(command=True)`. The missing `cmdi-redirection` pattern (FIND-2) would not have been caught.
- **Fix:** Add `TestSanitizeStringCommandInjection` with tests for shell metacharacters, common commands, and redirection.
- **Decision:** fix
- **Status:** ✅ done

---

### FIND-9: `sanitize_string` encodes `&` before other entities — double-encoding

- **Category:** CAT-3
- **Severity:** P1
- **File:** `sanitizers/sanitize.py:104-106`
- **What:** The XSS encoding loop iterates the encoding dict:
  ```python
  for char, replacement in self._xss_encoding.items():
      result = result.replace(char, replacement)
  ```
  If `&` is encoded first (to `&amp;`), then when `<` is encoded to `&lt;`, the `&` in `&lt;` is NOT re-encoded (since we already passed `&`). This is correct **only if `&` is first in the dict**. In Python 3.7+ dicts preserve insertion order, and the PATTERNS encoding dict has `&` first. But this is fragile — if patterns.json reorders the encoding map, `<` would become `&amp;lt;` (double-encoded).
- **Why:** Silent double-encoding if dict order changes. Defense: encode `&` first explicitly, then the rest.
- **Fix:** Encode `&` first explicitly, then iterate remaining:
  ```python
  if '&' in self._xss_encoding:
      result = result.replace('&', self._xss_encoding['&'])
  for char, replacement in self._xss_encoding.items():
      if char != '&':
          result = result.replace(char, replacement)
  ```
- **Decision:** fix
- **Status:** ✅ done

---

### FIND-10: `TEST_VECTORS.json` XSS expectations don't match architecture

- **Category:** CAT-1
- **Severity:** P2 (spec issue, not code)
- **File:** `spec/TEST_VECTORS.json`
- **What:** Test vectors for `sanitize_string` XSS expect `&lt;` in the output (e.g., `<script>alert('xss')</script>` should contain `&lt;`). But the architecture decision is "remove before encode" — so `<script>` tags are fully removed first, leaving no `<` to encode. The test vectors describe a different behavior (encode-only).
- **Why:** Conformance tests can't pass against either the spec or the code — they disagree.
- **Fix:** Update `TEST_VECTORS.json` XSS cases to match "remove before encode" behavior. The assertions should check that dangerous content is ABSENT, not that it's HTML-encoded.
- **Decision:** defer — cross-SDK spec change, coordinate with Node.js
- **Status:** deferred

---

## Decisions Log

| FIND | Decision | Reason |
|------|----------|--------|
| FIND-1 | fix | No conformance test coverage at all |
| FIND-2 | fix | Missing pattern + divergence from source of truth |
| FIND-3 | fix | Wasted thread, inconsistent with async |
| FIND-4 | fix | Redis store unusable with sync RateLimiter |
| FIND-5 | fix | Trivial, consistency with Node.js |
| FIND-6 | fix | Inconsistency between sync/async return shape |
| FIND-7 | fix | Trivial, removes deprecation warning |
| FIND-8 | fix | Zero test coverage for a default-on feature |
| FIND-9 | fix | Fragile encoding order |
| FIND-10 | defer | Cross-SDK spec change needed |

---

## Fix Priority Order

| Priority | Finding | Why |
|----------|---------|-----|
| **P1** | FIND-2 | Missing security pattern + single-source-of-truth violation |
| **P1** | FIND-4 | Redis store crashes with sync RateLimiter |
| **P1** | FIND-9 | Fragile encoding order, potential double-encoding |
| **P1** | FIND-1 | No conformance tests at all |
| **P2** | FIND-3 | Wasted cleanup thread with external store |
| **P2** | FIND-5 | Magic numbers across codebase |
| **P2** | FIND-6 | Missing `reset` key in async paths |
| **P2** | FIND-7 | Deprecated `utcnow()` |
| **P2** | FIND-8 | No command injection tests |
| **defer** | FIND-10 | Cross-SDK test vector update |

---

## Sign-Off

✅ **Signed off — 2026-03-10**

All 10 findings resolved (9 fixed, 1 deferred cross-SDK). Test count: 240 passed, 1 skipped, 0 warnings.

**Re-audit is required if:**
- A new feature is added to `spec/API_SPEC.md`
- A new pattern is added to `packages/core/patterns.json`
- Test count drops below 240
- A P0 regression is discovered
