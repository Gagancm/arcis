# Audit State — C# (`arcis-csharp`)

**Status:** ⬜ NOT STARTED
**Last audited:** never
**Test count:** unknown
**Package path:** `packages/arcis-csharp`

---

## Checklist Results

All items PENDING. Run a full triage pass before filling these in.

### CAT-1: Spec Compliance
- [ ] Every function in `spec/API_SPEC.md` exists and is exported — **PENDING**
- [ ] Every config option in spec is wired up with correct default — **PENDING**
- [ ] All `spec/TEST_VECTORS.json` cases are exercised in tests — **PENDING**

### CAT-2: Pattern Coverage
- [ ] All patterns in `packages/core/patterns.json` are implemented — **PENDING**
- [ ] ReDoS-safe variants used where `redos_safe: false` — **PENDING**
- [ ] No local duplicate pattern list — **PENDING**

### CAT-3: Security Logic
- [ ] Sanitization: remove before encode — **PENDING**
- [ ] Reject mode: returns error, does not pass partial input — **PENDING**
- [ ] Prototype pollution keys blocked at traversal — **PENDING**
- [ ] NoSQL operators: all keys blocked — **PENDING**
- [ ] Redis store: timestamps in consistent units — **PENDING**
- [ ] Rate limiter: per-key isolation — **PENDING**

### CAT-4: Resource Management
- [ ] Background intervals/threads have shutdown path — **PENDING**
- [ ] Cleanup not created when external store provided — **PENDING**
- [ ] Store constructors validate bounds — **PENDING**

### CAT-5: Type Safety
- [ ] No untyped casts in public API paths — **PENDING**
- [ ] Custom validator return types don't silently accept null — **PENDING**
- [ ] Store interface return types consistent — **PENDING**

### CAT-6: Test Quality
- [ ] Prototype pollution test creates real own-key — **PENDING**
- [ ] Fake timer / mock cleanup in `finally` — **PENDING**
- [ ] Test server lifecycle guarded — **PENDING**
- [ ] Threat collection tests assert `.original` and `.pattern` — **PENDING**
- [ ] Test helpers use actual constants — **PENDING**

### CAT-7: Cross-SDK Consistency

Fill this table during triage:

| Feature | C# | Node.js baseline | Match? |
|---------|----|-----------------|--------|
| SLEEP/BENCHMARK SQL patterns | PENDING | ✅ | — |
| Script tag ReDoS-safe | PENDING | ✅ | — |
| SafeLogger extends defaults | PENDING | ✅ | — |
| Redis timestamps in ms | PENDING | N/A | — |
| Cleanup interval skipped for ext. store | PENDING | ✅ | — |
| Magic numbers → named constants | PENDING | ✅ | — |
| Feature names match spec | PENDING | ✅ | — |
| Return types match spec | PENDING | ✅ | — |
| Default values match spec | PENDING | ✅ | — |

### CAT-8: Dead Code / Hygiene
- [ ] No unused imports or exports — **PENDING**
- [ ] No magic numbers — **PENDING**
- [ ] No hardcoded fallback patterns diverging from `patterns.json` — **PENDING**

---

## Notes

- Project file may still reference old name `Shield.csproj` — check and update if so
- Test project may still be `Shield.Tests.csproj` — check and update

---

## Findings

None yet. Run triage to populate.

---

## Decisions Log

None yet.

---

## Sign-Off

Not signed off. Complete triage and Fix phases first.
