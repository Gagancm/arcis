## Shield repo structure (monorepo)

Shield is a **contract-first** security framework implemented as multiple language SDKs in one repo.

The most important rule: **the contract is the source of truth**. Language implementations must match behavior defined in `spec/` and should consume the shared rule database in `packages/core/`.

This document is intended to be the **single place** that explains:
- how the repo is organized,
- how the “big library” model works (spec + conformance + shared DB),
- what conventions to follow when adding languages/frameworks,
- and what cleanup work is needed to keep Shield scalable and consistent.

---

## What’s authoritative

- **Behavior contract**: `spec/API_SPEC.md`
  - Defines required modules (sanitize, rate limit, headers, validate, logger, error handler)
  - Defines default behaviors and options
- **Conformance tests**: `spec/TEST_VECTORS.json`
  - Shared test vectors that every language SDK must pass
- **Shared rule database**: `packages/core/patterns.json`
  - Regex/pattern rules, default headers, sensitive keys, validation regex, limits (max size/depth), etc.

Practical rule:
- If an SDK behavior differs from `spec/` or fails `TEST_VECTORS.json`, the SDK is wrong (not the contract).

---

## Current directory map

```
shield/
├── README.md
├── PLAN.md
├── FUTURE_AI_ROADMAP.md
├── docs/
│   └── code-structure.md
├── spec/
│   ├── API_SPEC.md
│   └── TEST_VECTORS.json
├── packages/
│   ├── core/
│   │   └── patterns.json
│   ├── shield-node/
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── src/index.ts
│   │   └── tests/index.test.ts
│   ├── shield-go/
│   │   ├── shield.go
│   │   ├── shield_test.go
│   │   ├── gin/gin.go
│   │   └── echo/echo.go
│   ├── shield-python/
│   │   ├── pyproject.toml
│   │   ├── README.md
│   │   ├── shield/          (Python SDK implementation A)
│   │   ├── shieldpy/        (Python SDK implementation B)
│   │   └── tests/
│   ├── shield-java/
│   │   └── src/main/java/io/shield/Shield.java
│   └── shield-csharp/
│       └── src/Shield.cs
└── examples/
    └── redis-store/
        ├── README.md
        ├── node-redis-store.ts
        ├── python-redis-store.py
        └── go-redis-store.go
```

Notes:
- Some folders referenced in `README.md` (like `docs/` content beyond this file, root `tests/`, `scripts/`) are not present yet.
- Python currently has two parallel namespaces (`shield/` and `shieldpy/`). This should be unified to a single public package to avoid confusion and drift.

---

## The “big library” model (single-language vs multi-language SDKs)

There are two common scaling patterns:

### Pattern A: One language, many frameworks

This is “multi-framework in the same ecosystem” (e.g., React/Vue/Svelte in JS).

- **Core engine**: framework-agnostic logic (state machine, algorithms)
- **Adapters**: thin glue to each framework
- **Consistent defaults**: same outcomes regardless of adapter

### Pattern B: Many languages (AWS SDK / gRPC / OpenTelemetry style)

This is “multi-language SDK family”. There is no single shared runtime; consistency comes from:

- **Normative spec**: defines behavior and API shape
- **Conformance**: shared tests (test vectors) that every SDK runs
- **Shared data model**: patterns/headers/sensitive keys DB that is versioned
- **Release discipline**: compatibility and deprecation policy across SDKs

Shield is Pattern B at the repo level, and Pattern A inside each language (core vs adapters).

---

## Design principles (how big libraries stay consistent)

- **Contract-first**: spec + test vectors define behavior; code follows.
- **Single source of patterns**: `packages/core/patterns.json` must be the shared baseline.
- **Thin adapters, strong core**:
  - Core = sanitize/validate/redact/rate-limit/headers/error-handling behavior
  - Adapters = framework glue (Express/FastAPI/Django/Gin/Echo/etc.)
- **Safe defaults**: enable key protections by default; allow opt-out per feature.
- **Fail-safe behavior**:
  - Rate limiting: typically fail-open on store errors to avoid self-DoS
  - Sanitization: apply size/depth limits to prevent resource exhaustion
- **Versioned contract**: changes to `patterns.json` / `API_SPEC.md` must be versioned and backward compatibility considered.

---

## Policy modes (recommended to add to the spec early)

To make Shield usable in real production rollouts without breaking apps, standardize a “policy mode” across SDKs:

- `enforce`: block request / return error (strict mode)
- `sanitize`: mutate values (current default behavior in many places)
- `audit`: do not mutate; emit a structured security event

Why it matters:
- Teams can start with `audit`, then move to `sanitize/enforce` safely.
- It gives you a consistent framework story across all languages.

---

## Package layout conventions (recommended)

Each language package should follow the same internal separation:

- `core/` (or equivalent): pure logic, framework-agnostic
- `adapters/` (or framework folders): middleware / decorators / interceptors
- `tests/`:
  - unit tests
  - conformance tests mapping to `spec/TEST_VECTORS.json`
- `examples/` (optional): minimal runnable demos

Example target layout:

```
packages/shield-<lang>/
├── <lang-native core code>
├── adapters/
│   ├── <framework-1>/
│   └── <framework-2>/
└── tests/
    ├── unit/
    └── conformance/   (must cover TEST_VECTORS.json)
```

---

## “Core DB” consumption rule (important)

Every SDK must implement one of these strategies:

- **Runtime bundle**: ship `patterns.json` inside the package and load it at runtime
- **Build-time codegen**: generate native constants/types from `patterns.json` during build

Avoid re-typing patterns directly in code, because it causes cross-language drift.

---

## Versioning and compatibility (recommended structure)

Big SDK families typically choose one of these:

### Option 1: One version across the whole Shield family

- All SDKs release as “Shield vX.Y.Z”.
- Pros: simpler marketing, easier to reason about “what version of Shield are we on?”
- Cons: forces synchronized releases across languages.

### Option 2: Spec/core version + per-language SDK versions

- `spec/` + `packages/core/` define “Shield Contract vA.B”.
- Each SDK can have its own version but must declare compatibility with a contract version.
- Pros: decouples SDK release cadence.
- Cons: adds metadata and coordination requirements.

Minimum compatibility rules:
- `spec/API_SPEC.md` changes must be versioned (and ideally backwards compatible).
- `spec/TEST_VECTORS.json` changes should be additive when possible (new tests, not changing old expectations).
- `packages/core/patterns.json` should be versioned and validated (schema + changelog).

---

## Conformance testing rules (recommended)

Each language SDK should:
- Map `spec/TEST_VECTORS.json` into native tests.
- Add additional unit tests for language-specific edge cases.
- Treat conformance as a release gate (don’t publish if conformance fails).

---

## Adding a new language SDK

1. Create `packages/shield-<language>/`
2. Implement modules required by `spec/API_SPEC.md`
   - sanitize, rate limit, headers, validate, logger, error handler
3. Consume `packages/core/patterns.json` (runtime or codegen)
4. Add conformance tests mapped to `spec/TEST_VECTORS.json`
5. Add minimal examples under `examples/` (optional but recommended)
6. Add publishing/build metadata for that ecosystem (Maven/NuGet/go.mod/etc.)

---

## Known cleanup items (structural)

- Unify Python into **one** public namespace (`shield` recommended) and remove the other (`shieldpy`) or demote it to a compatibility wrapper.
- Ensure Go/Java/C# have standard build files:
  - Go: `go.mod` under `packages/shield-go/`
  - Java: `pom.xml` or `build.gradle`
  - C#: `.csproj`
- Align README install/import paths with the actual package names and publishing targets.

---

## Naming and packaging consistency checklist

Before publishing any SDK:
- The README install instructions match the actual package name and import path.
- The package contains exactly one “main” entrypoint (avoid duplicate namespaces like `shield` + `shieldpy`).
- The SDK declares what contract/core DB version it implements.


