# Audit State — Python (`arcis-python`)

**Status:** 🔴 IN PROGRESS — triage complete, Fix phase not started
**Last audited:** 2026-03-10
**Test count:** unknown (not yet run)
**Package path:** `packages/arcis-python`

---

## Checklist Results

> Items are PASS / FAIL / SKIP / PENDING. All FAIL items have findings below.

### CAT-1: Spec Compliance
- [ ] Every function in `spec/API_SPEC.md` exists and is exported — **PENDING**
- [ ] Every config option in spec is wired up with correct default — **PENDING**
- [ ] All `spec/TEST_VECTORS.json` cases are exercised in tests — **PENDING**

### CAT-2: Pattern Coverage
- [x] All patterns in `packages/core/patterns.json` are implemented — **FAIL** → FIND-1, FIND-4
- [x] ReDoS-safe variants used where `redos_safe: false` — **FAIL** → FIND-2
- [x] No local duplicate pattern list — **FAIL** → FIND-4 (embedded fallback diverges from `patterns.json`)

### CAT-3: Security Logic
- [ ] Sanitization: remove before encode — **PENDING**
- [ ] Reject mode: returns error, does not pass partial input — **PENDING**
- [ ] Prototype pollution keys blocked at traversal — **PENDING**
- [ ] NoSQL operators: all keys blocked — **PENDING**
- [x] Redis store: timestamps in consistent units — **FAIL** → FIND-3 (P0)
- [ ] Rate limiter: per-key isolation — **PENDING**

### CAT-4: Resource Management
- [ ] Background intervals have shutdown path — **PENDING**
- [ ] Cleanup interval not created when external store provided — **PENDING**
- [x] Store constructors validate bounds — **FAIL** → FIND-6 (no bounds check on `windowMs`)

### CAT-5: Type Safety
- [ ] No `any` / untyped casts in public API paths — **PENDING**
- [x] Custom validator return types don't silently accept `None` — **PENDING**
- [ ] Store interface return types consistent — **PENDING**

### CAT-6: Test Quality
- [ ] Prototype pollution test creates real own-key — **PENDING**
- [ ] Fake timer / mock cleanup in `finally` — **PENDING**
- [ ] Test server lifecycle guarded — **PENDING**
- [ ] Threat collection tests assert `.original` and `.pattern` — **PENDING**
- [ ] Test helpers use actual constants — **PENDING**

### CAT-7: Cross-SDK Consistency

| Feature | Python | Node.js baseline | Match? |
|---------|--------|-----------------|--------|
| SLEEP/BENCHMARK SQL patterns | ❌ Missing in fallback | ✅ | No — FIND-1 |
| Script tag ReDoS-safe | ❌ Uses unsafe `pattern` | ✅ | No — FIND-2 |
| SafeLogger extends defaults | N/A (no `WithKeys` fn) | ✅ | N/A |
| Redis timestamps in ms | ❌ Broken (P0) | N/A | — FIND-3 |
| Cleanup interval skipped for ext. store | PENDING | ✅ | — |
| Magic numbers → named constants | PENDING | ✅ | — |
| `data:` false positive scope | ⚠️ Same as all SDKs | ⚠️ | — FIND-7 |
| Docstring import paths correct | ❌ Wrong path | N/A | — FIND-8 |
| `increment()` creates entry on first call | ❌ Silent no-op | ✅ | — FIND-5, FIND-6 |

### CAT-8: Dead Code / Hygiene
- [ ] No unused imports or exports — **PENDING**
- [ ] No magic numbers — **PENDING**
- [x] No hardcoded fallback patterns diverging from `patterns.json` — **FAIL** → FIND-4

---

## Findings

---

### FIND-1: SLEEP/BENCHMARK SQL patterns missing in embedded fallback
- **Category:** CAT-2, CAT-7
- **Severity:** P1
- **File:** `packages/arcis-python/arcis/core.py` line 19, `get_embedded_patterns()`
- **What:** `patterns.json` defines `sqli-sleep` and `sqli-benchmark`. When installed via pip, `PATTERNS_PATH` resolves outside the package and the embedded fallback is used — which is missing these patterns (and several others: `sqli-boolean-string`, `path-null-byte`, shell redirection, LDAP, XML/XXE).
- **Why:** Production pip-installed deployments silently use fewer patterns. Time-based blind SQL injection (`SLEEP(5)`) passes through unblocked.
- **Fix:** Package `patterns.json` as Python package data and load via `importlib.resources`:
  ```python
  from importlib.resources import files
  data = files("arcis").joinpath("data/patterns.json").read_text()
  ```
  Or copy `patterns.json` into `arcis/data/` and reference as `Path(__file__).parent / "data" / "patterns.json"`.
- **Decision:** fix
- **Status:** open

---

### FIND-2: Python uses ReDoS-unsafe script tag regex
- **Category:** CAT-2, CAT-7
- **Severity:** P1
- **File:** `packages/arcis-python/arcis/core.py` line 138–140
- **What:** `Sanitizer.__init__()` loads XSS patterns using `rule["pattern"]`. For the script tag rule, `patterns.json` has `"redos_safe": false` and a safe alternative in `"pattern_safe"`. Python ignores the safe variant. The unsafe pattern `<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>` has nested quantifiers causing exponential backtracking with adversarial input.
- **Why:** A crafted request (e.g., `<script` + thousands of chars) can hang the Python process for seconds — DoS.
- **Fix:** Prefer `pattern_safe` when present:
  ```python
  pattern_str = rule.get("pattern_safe") or rule["pattern"]
  self._xss_patterns.append(re.compile(pattern_str, flags))
  ```
- **Decision:** fix
- **Status:** open

---

### FIND-3: Redis rate limiting always treats entries as expired (P0)
- **Category:** CAT-3
- **Severity:** P0
- **File:** `packages/arcis-python/arcis/stores/redis.py`
- **What:** `RateLimiter.check()` passes `reset_time = now + window_seconds` (seconds). `RedisRateLimitStore.set()` stores that seconds value. `RedisRateLimitStore.get()` then does:
  ```python
  if reset_time < time.time() * 1000:  # seconds < milliseconds → ALWAYS TRUE
      return None  # always expired
  ```
  Because `get()` always returns `None`, every request takes the "new window" branch and gets `count=1`. The rate limiter accumulates nothing. Same bug in `AsyncRedisRateLimitStore`.
- **Why:** Any deployment using Redis for distributed rate limiting has zero protection. Unlimited requests pass through.
- **Fix:** Standardize on milliseconds throughout:
  - `core.py RateLimiter.check()`: pass `now * 1000 + self.window_ms`
  - `redis.py set()` docstring: annotate `reset_time: float  # Unix timestamp in milliseconds`
  - The `get()` comparison `reset_time < time.time() * 1000` is then correct
  - Apply same fix to `AsyncRedisRateLimitStore`
- **Decision:** fix
- **Status:** open

---

### FIND-4: `patterns.json` load path fails for installed packages
- **Category:** CAT-2, CAT-8
- **Severity:** P1
- **File:** `packages/arcis-python/arcis/core.py` line 19
- **What:**
  ```python
  PATTERNS_PATH = Path(__file__).parent.parent.parent / "core" / "patterns.json"
  ```
  Works in repo. In pip-installed package, this resolves outside `site-packages` entirely and fails silently, falling back to the incomplete embedded patterns (see FIND-1).
- **Why:** Silent degradation of security in production installs.
- **Fix:** Same as FIND-1 — use `importlib.resources` or copy file to `arcis/data/`.
- **Decision:** fix (same fix as FIND-1, resolve together)
- **Status:** open

---

### FIND-5: `AsyncInMemoryStore.increment()` silent no-op on missing key
- **Category:** CAT-4, CAT-7
- **Severity:** P1
- **File:** `packages/arcis-python/arcis/fastapi.py` line 84–91
- **What:**
  ```python
  async def increment(self, key: str) -> int:
      async with self._lock:
          entry = self._store.get(key)
          if entry:
              entry.count += 1
              return entry.count
          return 1  # key doesn't exist — returns 1 but never creates entry
  ```
  Every call on a missing key returns `1`. Count never accumulates.
- **Why:** Any custom integration calling `increment()` without `set()` first silently fails to rate-limit.
- **Fix:** Create the entry on first call, or raise `KeyError` to signal the caller must call `set()` first. Match the sync fix when applied.
- **Decision:** fix
- **Status:** open

---

### FIND-6: `InMemoryStore.increment()` same bug (sync version)
- **Category:** CAT-4
- **Severity:** P1
- **File:** `packages/arcis-python/arcis/core.py` line 292–299
- **What:** `InMemoryStore.increment()` returns `1` without creating an entry on a missing key. Subsequent calls also return `1`. Count never tracked.
- **Why:** Same as FIND-5 (sync version of the same bug).
- **Fix:** Create the entry on first increment.
- **Decision:** fix (same fix as FIND-5)
- **Status:** open

---

### FIND-7: `data:` XSS pattern causes false positives
- **Category:** CAT-3
- **Severity:** P2
- **File:** Python embedded patterns in `get_embedded_patterns()` and via `patterns.json`
- **What:** Pattern `/data:/gi` matches `data:` anywhere — including `"metadata: value"` and `"Your stored data: 42"`. These legitimate strings are silently corrupted.
- **Why:** False positive data corruption on valid API inputs.
- **Fix:** Tighten to `(?:^|[\s"'=])data:` or match specific dangerous MIME types only (`data:text/html`, `data:application/javascript`).
- **Decision:** defer (affects all SDKs equally — fix as a coordinated cross-SDK change)
- **Status:** deferred

---

### FIND-8: FastAPI docstring references wrong import path
- **Category:** CAT-8
- **Severity:** P2
- **File:** `packages/arcis-python/arcis/fastapi.py` lines 147, 319
- **What:** Docstrings show `from arcis.examples.redis_store import AsyncRedisRateLimitStore`. Correct path is `from arcis.stores.redis import AsyncRedisRateLimitStore`.
- **Why:** Users copying from docs get `ImportError`.
- **Fix:** Update both docstring examples.
- **Decision:** fix
- **Status:** open

---

### FIND-9: FastAPI JSON decode errors silently swallowed
- **Category:** CAT-3, CAT-4
- **Severity:** P2
- **File:** `packages/arcis-python/arcis/fastapi.py` line 419–424
- **What:**
  ```python
  except Exception:
      pass  # completely silent
  ```
  Malformed JSON body leaves `request.state.sanitized_body` unset. Handlers get `AttributeError` at a different location.
- **Why:** Misleading errors, hard to debug.
- **Fix:** At minimum `request.state.sanitized_body = None` in the except block. Optionally log the parse error.
- **Decision:** fix
- **Status:** open

---

## Decisions Log

| FIND | Decision | Reason |
|------|----------|--------|
| FIND-7 | defer | Cross-SDK issue; fix coordinated across all SDKs, not Python-only |

---

## Sign-Off

Not signed off. Complete Fix phase and re-run full checklist first.
