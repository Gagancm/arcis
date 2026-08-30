"""Dry-run behavior for FastAPI forwarded-header inspection."""

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware
from arcis.telemetry.client import AsyncTelemetryClient
from arcis.telemetry.types import TelemetryOptions


def test_dry_run_preserves_spoofed_header_and_records_would_deny():
    captured = []

    class _Capture(AsyncTelemetryClient):
        def record(self, event):  # type: ignore[override]
            captured.append(event)

    telemetry = _Capture(TelemetryOptions(endpoint="http://localhost:9999/v1/events"))
    app = FastAPI()
    app.add_middleware(
        ArcisMiddleware,
        dry_run=True,
        scanner_paths=False,
        bot=False,
        rate_limit=False,
        sanitize=False,
        graphql=False,
        mass_assign=False,
        ssrf=False,
        prompt_injection=False,
        telemetry=telemetry,
    )

    @app.get("/forwarded")
    async def forwarded(request: Request):
        return {"forwarded_for": request.headers.get("x-forwarded-for")}

    response = TestClient(app).get(
        "/forwarded",
        headers={"x-forwarded-for": "127.0.0.1"},
    )

    assert response.status_code == 200
    assert response.json() == {"forwarded_for": "127.0.0.1"}
    assert len(captured) == 1
    assert captured[0].decision == "would_deny"
    assert captured[0].vector == "header"
    assert captured[0].rule == "header/forwarded-loopback-spoof"
    assert captured[0].status == 200
