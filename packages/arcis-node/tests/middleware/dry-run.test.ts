/**
 * Dry-run mode + onSanitize callback tests (issue #47).
 *
 * Exercises the bundle middleware's `dryRun` and `onSanitize` options
 * end-to-end via a real Express server (createTestServer) so the
 * interception of res.status / res.json / res.end actually runs through
 * the same code path users hit.
 */

import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Request } from 'express';
import { arcis } from '../../src/middleware/main';
import type { SanitizeEvent } from '../../src/core/types';
import { createTestServer, TestServer } from '../setup';

interface DryRunInputFixture {
  name: string;
  request: {
    path_param: string;
    query: Record<string, string>;
    headers: Record<string, string>;
    cookies: Record<string, string>;
    body_raw: string;
  };
  expected_request_unchanged: boolean;
}

interface FixtureRequest extends Request {
  __rawFixtureBody?: Buffer;
}

const vectorsPath = resolve(__dirname, '..', '..', '..', '..', 'spec', 'TEST_VECTORS.json');
const dryRunInputFixtures = (
  JSON.parse(readFileSync(vectorsPath, 'utf8')) as {
    dry_run_input_preservation: { cases: DryRunInputFixture[] };
  }
).dry_run_input_preservation.cases;

describe('arcis() — onSanitize callback (issue #47)', () => {
  let testServer: TestServer;

  it('fires onSanitize for an XSS payload in body', async () => {
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      app.use((req, _res, next) => {
        // The arcis bundle inspects req.body, but body-parser hasn't run by
        // default in createTestServer. Wire one in for this test set.
        req.body = req.body ?? {};
        next();
      });
      const express = require('express');
      app.use(express.json());
      app.use(arcis({ rateLimit: false, onSanitize: (e) => events.push(e) }));
      app.post('/echo', (req, res) => res.json({ ok: true, body: req.body }));
    });

    await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: '<script>alert(1)</script>' }),
    });

    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].type).toBe('xss');
    expect(events[0].field).toBe('body');
    expect(events[0].pattern).toContain('<script>');

    await testServer.close();
  });

  it('fires onSanitize for a SQL payload in query', async () => {
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false, onSanitize: (e) => events.push(e) }));
      app.get('/q', (_req, res) => res.json({ ok: true }));
    });

    // UNION SELECT is a high-confidence SQL pattern that the detector
    // matches without ambiguity. Quote-based payloads ('OR 1=1) require
    // surrounding context the detector intentionally treats conservatively.
    await fetch(`${testServer.url}/q?id=1%20UNION%20SELECT%20*%20FROM%20users`);

    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events.some((e) => e.type === 'sql' && e.field === 'query')).toBe(true);

    await testServer.close();
  });

  it('does NOT fire onSanitize on a clean request', async () => {
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false, onSanitize: (e) => events.push(e) }));
      app.get('/q', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/q?name=alice&id=42`);
    expect(res.status).toBe(200);
    expect(events).toHaveLength(0);

    await testServer.close();
  });

  it('catches errors thrown from the callback (fail-open)', async () => {
    // A buggy observer must NOT break the response path. Verifies the
    // try/catch around the callback invocation.
    const onSanitize = vi.fn(() => {
      throw new Error('observer is buggy');
    });
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false, onSanitize }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    const res = await fetch(`${testServer.url}/?q=<script>alert(1)</script>`);
    expect(res.status).toBe(200);
    expect(onSanitize).toHaveBeenCalled();

    await testServer.close();
  });

  it('zero overhead when onSanitize is omitted', async () => {
    // Observer middleware should not be inserted when there's no callback.
    // We can't directly count middlewares without exposing internals, so
    // sanity-check via a clean request that obviously passes.
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: false }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });
    const res = await fetch(`${testServer.url}/`);
    expect(res.status).toBe(200);
    await testServer.close();
  });
});

describe('arcis() — dry-run mode (issue #47)', () => {
  let testServer: TestServer;

  it('does NOT block on XSS payload when dryRun: true (vs block: true that would)', async () => {
    // Without dry-run, block: true would return 403. With dry-run, the
    // request passes through and the handler runs (200).
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      const express = require('express');
      app.use(express.json());
      app.use(
        arcis({
          rateLimit: false,
          block: true,
          dryRun: true,
          onSanitize: (e) => events.push(e),
        }),
      );
      app.post('/api', (_req, res) => res.json({ reached: true }));
    });

    const res = await fetch(`${testServer.url}/api`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: '<script>alert(1)</script>' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { reached: boolean };
    expect(body.reached).toBe(true);
    expect(events.some((e) => e.type === 'xss')).toBe(true);

    await testServer.close();
  });

  it('does NOT return 429 when dryRun: true even past the rate limit', async () => {
    // Limiter would normally return 429 after 2 requests. In dry-run mode
    // it shouldn't actually block — all 5 should succeed.
    testServer = await createTestServer((app) => {
      app.use(
        arcis({
          rateLimit: { max: 2, windowMs: 60_000 },
          dryRun: true,
        }),
      );
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    for (let i = 0; i < 5; i++) {
      const res = await fetch(`${testServer.url}/`);
      expect(res.status).toBe(200);
    }

    await testServer.close();
  });

  it('still surfaces X-RateLimit-* headers in dry-run mode', async () => {
    // The headers reflect the would-have-been decision so dashboards can
    // show "you'd have been rate-limited" without the 429 hitting prod.
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: { max: 1, windowMs: 60_000 }, dryRun: true }));
      app.get('/', (_req, res) => res.json({ ok: true }));
    });

    await fetch(`${testServer.url}/`);
    const res = await fetch(`${testServer.url}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get('X-RateLimit-Limit')).toBe('1');
    // Remaining clamps at 0 once limit is exceeded; the limiter still
    // reports the would-have-been state.
    expect(res.headers.get('X-RateLimit-Remaining')).toBe('0');

    await testServer.close();
  });

  it('marks a suppressed rate limit as would_deny', async () => {
    testServer = await createTestServer((app) => {
      app.use(arcis({ rateLimit: { max: 1, windowMs: 60_000 }, dryRun: true }));
      app.get('/', (req, res) => res.json({
        reached: true,
        decision: req.__arcis?.decision,
        vector: req.__arcis?.vector,
      }));
    });

    await fetch(`${testServer.url}/`);
    const res = await fetch(`${testServer.url}/`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      reached: true,
      decision: 'would_deny',
      vector: 'rate-limit',
    });

    await testServer.close();
  });

  it('does NOT strip XSS from request body in dryRun mode', async () => {
    // Dry-run evaluates the immutable observer path. It must not require a
    // separate sanitize:false escape hatch to preserve the request.
    const events: SanitizeEvent[] = [];
    testServer = await createTestServer((app) => {
      const express = require('express');
      app.use(express.json());
      app.use(
        arcis({
          rateLimit: false,
          block: true,
          dryRun: true,
          onSanitize: (e) => events.push(e),
        }),
      );
      app.post('/echo', (req, res) => res.json(req.body));
    });

    const res = await fetch(`${testServer.url}/echo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: '<script>alert(1)</script>' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { q: string };
    expect(body.q).toBe('<script>alert(1)</script>');
    expect(events.some((e) => e.type === 'xss')).toBe(true);

    await testServer.close();
  });

  it('does not transform benign business data while observing threats', async () => {
    testServer = await createTestServer((app) => {
      const express = require('express');
      app.use(express.json());
      app.use(arcis({ rateLimit: false, block: true, dryRun: true }));
      app.post('/api', (req, res) => res.json(req.body));
    });

    const res = await fetch(`${testServer.url}/api`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        note: 'Use the -- flag; it works',
        path: 'docs/../README.md',
      }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      note: 'Use the -- flag; it works',
      path: 'docs/../README.md',
    });

    await testServer.close();
  });

  it.each(dryRunInputFixtures)(
    'preserves shared fixture $name across every Express request surface',
    async (fixture) => {
      expect(fixture.expected_request_unchanged).toBe(true);
      testServer = await createTestServer((app) => {
        app.use(arcis({ rateLimit: false, block: true, dryRun: true }));
        app.post('/preserve/:fixtureId', (req, res) => {
          const fixtureRequest = req as FixtureRequest;
          res.json({
            rawBody: fixtureRequest.__rawFixtureBody?.toString('utf8'),
            parsedBody: req.body,
            query: req.query,
            params: req.params,
            fixtureHeader: req.headers['x-arcis-fixture'],
            cookieHeader: req.headers.cookie,
          });
        });
      }, {
        json: {
          verify: (req: FixtureRequest, _res: unknown, body: Buffer) => {
            req.__rawFixtureBody = Buffer.from(body);
          },
        },
      });

      const query = new URLSearchParams(fixture.request.query).toString();
      const fixtureHeader = fixture.request.headers['x-arcis-fixture'];
      const cookieValue = fixture.request.cookies.arcis_note;
      const res = await fetch(
        `${testServer.url}/preserve/${encodeURIComponent(fixture.request.path_param)}?${query}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-arcis-fixture': fixtureHeader,
            cookie: `arcis_note=${cookieValue}`,
          },
          body: fixture.request.body_raw,
        },
      );

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        rawBody: fixture.request.body_raw,
        parsedBody: JSON.parse(fixture.request.body_raw),
        query: fixture.request.query,
        params: { fixtureId: fixture.request.path_param },
        fixtureHeader,
        cookieHeader: `arcis_note=${cookieValue}`,
      });

      await testServer.close();
    },
  );
});
