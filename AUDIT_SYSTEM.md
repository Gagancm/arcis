# Arcis — Structured Audit System

> **Permanent procedure.** Do not delete or modify the checklist categories or priority definitions. Per-language state lives in `audit/{language}.md`.

---

## Why This Exists

The old "find everything wrong" approach creates infinite loops: each audit finds more issues, no language ever reaches a signed-off state, and SKIP decisions are re-debated every session. This system fixes that by:

1. Providing a **finite checklist** (yes/no questions only — not "find improvements")
2. Keeping **per-language state files** that persist triage decisions forever
3. Defining a clear **done** condition: every checklist item is PASS or documented SKIP

---

## Priority Definitions

| Priority | Meaning | Action |
|----------|---------|--------|
| P0 | Security vulnerability or completely broken core functionality | Block release, fix immediately |
| P1 | Missing/wrong behavior, API inconsistency, broken contract | Fix before shipping |
| P2 | Reliability issue, fixable if trivial (< 5 lines), defer if complex | Fix if trivial, else defer |
| SKIP | Not worth fixing — reason documented, decision is permanent | Write reason, never re-debate |

---

## The Fixed Checklist

> **Rules:**
> - Every item is a yes/no question answered PASS or FAIL — never "find more"
> - Do NOT add new items to this checklist mid-pass
> - All 8 categories must be completed before sign-off
> - SKIP answers are permanent: the same item cannot be re-opened in the next audit unless the code changes

---

### CAT-1: Spec Compliance

- [ ] Every function in `spec/API_SPEC.md` exists and is exported
- [ ] Every config option in spec is wired up with correct default
- [ ] All `spec/TEST_VECTORS.json` cases are exercised in tests

### CAT-2: Pattern Coverage

- [ ] All patterns in `packages/core/patterns.json` are implemented (compare exhaustively — list each pattern ID)
- [ ] ReDoS-safe variants used where `redos_safe: false` in `patterns.json`
- [ ] No pattern list defined locally that duplicates/diverges from core (single source of truth)

### CAT-3: Security Logic

- [ ] Sanitization: remove before encode (not encode then remove)
- [ ] Reject mode: returns error, does NOT pass partially-sanitized input to handler
- [ ] Prototype pollution keys blocked at object traversal level
- [ ] NoSQL operators: all keys in `NOSQL_DANGEROUS_KEYS` / `patterns.json` are blocked
- [ ] Redis store: timestamps in consistent units (ms everywhere)
- [ ] Rate limiter: per-key isolation works (two different keys are independent)

### CAT-4: Resource Management

- [ ] Every background interval/goroutine/thread has a documented shutdown path (`close()`)
- [ ] Cleanup interval not created when external store is provided
- [ ] Store constructors validate bounds (`windowMs`, `ttl`) — throw/panic on invalid values

### CAT-5: Type Safety

- [ ] No `any` casts in public API paths
- [ ] Custom validator / callback return types don't silently accept `undefined` / `None`
- [ ] Store interface return types consistent (null vs undefined vs None) — matches spec

### CAT-6: Test Quality

- [ ] Prototype pollution test creates real own-key (use `JSON.parse`, not object literal in JS/TS)
- [ ] Fake timer / mock cleanup in `finally` block (not just in happy path)
- [ ] Test server lifecycle guarded — `close()` called even on setup failure
- [ ] Threat collection tests assert `.original` and `.pattern` fields (not just `.type`)
- [ ] Test helpers (e.g. `hasDangerousKeys`) use the actual constants, not hardcoded subsets

### CAT-7: Cross-SDK Consistency

Fill the consistency table (compare this language against Node.js as baseline):

| Feature | This SDK | Node.js | Match? |
|---------|----------|---------|--------|
| SLEEP/BENCHMARK SQL patterns | | ✅ | |
| Script tag regex safety (ReDoS-safe) | | ✅ | |
| SafeLogger extends defaults (not replaces) | | ✅ | |
| Redis timestamps in ms | | N/A | |
| Cleanup interval skipped for external store | | ✅ | |
| Magic numbers → named constants | | ✅ | |
| Feature names match spec naming | | ✅ | |
| Return types match spec | | ✅ | |
| Default values match spec | | ✅ | |

### CAT-8: Dead Code / Hygiene

- [ ] No unused imports or exports
- [ ] No magic numbers — all bare integers/strings in logic should be named constants
- [ ] No hardcoded fallback patterns that diverge from `patterns.json`

---

## Workflow: One Language at a Time

```
Phase 1 — TRIAGE (read-only)
  Run the 8-category checklist against the language.
  For each item: PASS / FAIL.
  For each FAIL: write a finding (file, line, what, why it matters, severity P0/P1/P2/SKIP).
  SKIP reason must be written down. It persists forever — never re-debated.
  No fixing happens in this phase.

Phase 2 — FIX
  Fix all P0 and P1 findings.
  P2 findings: fix if trivial (< 5 lines), defer if complex (write why).
  SKIP findings: mark done, confirm reason is written.
  Run tests after every fix. Test count must stay at N/N passing.

Phase 3 — SIGN-OFF
  Re-run checklist. Every item must be PASS or documented SKIP.
  Write sign-off block: date, test count, what would trigger re-audit.
  Language is now "complete". Do NOT re-audit unless:
    - New feature added to spec/API_SPEC.md
    - New pattern added to packages/core/patterns.json
    - Test count drops
    - A P0 regression is discovered
```

---

## Language Order

| Order | Language | State File | Status |
|-------|----------|-----------|--------|
| 1 | Node.js | `audit/node.md` | ✅ Complete — 423/423 signed off |
| 2 | Python | `audit/python.md` | 🔴 In progress — P0 + P1 open |
| 3 | Go | `audit/go.md` | 🟠 Not started — known P1 issues |
| 4 | C# | `audit/csharp.md` | ⬜ Not started |
| 5 | Java | `audit/java.md` | ⬜ Not started |

---

## Critical Reference Files (read before auditing any language)

| File | Purpose |
|------|---------|
| `spec/API_SPEC.md` | Ground truth: what every SDK must expose |
| `spec/TEST_VECTORS.json` | Input/output cases all languages must cover |
| `packages/core/patterns.json` | The one true pattern source (compare exhaustively) |
| `arcis-audit-report.md` | Legacy findings — seeded into python.md and go.md |
| `D:\Projects\cyber-security\DEFINITIVE_ISSUE_LIST.md` | Node.js completed issues (reference) |

---

## How to Write a Finding

Each finding in `audit/{language}.md` must include:

```
### FIND-{N}: {short title}
- **Category:** CAT-{1-8}
- **Severity:** P0 / P1 / P2 / SKIP
- **File:** path/to/file.ext (line N)
- **What:** exact problem, with code snippet if it helps
- **Why:** real-world impact if left unfixed
- **Fix:** concrete steps or code showing the fix
- **Decision:** fix / skip / defer — written once, permanent
- **Status:** open / done / skipped / deferred
```
