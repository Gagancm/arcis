"""Shared production-shaped inputs remain exact in FastAPI dry-run mode."""

import json
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi import FastAPI, Request
from starlette.responses import Response
from starlette.testclient import TestClient

from arcis.fastapi import ArcisMiddleware


_VECTORS_PATH = Path(__file__).parents[4] / "spec" / "TEST_VECTORS.json"
with _VECTORS_PATH.open(encoding="utf-8") as _vectors_file:
    _FIXTURES = json.load(_vectors_file)["dry_run_input_preservation"]["cases"]


def _build_preservation_app() -> TestClient:
    app = FastAPI()
    app.add_middleware(
        ArcisMiddleware,
        block=True,
        dry_run=True,
        rate_limit=False,
        headers=False,
    )

    @app.post("/preserve/{fixture_id}")
    async def preserve(fixture_id: str, request: Request):
        raw_body = await request.body()
        parsed_body = await request.json()
        return {
            "raw_body": raw_body.decode("utf-8"),
            "parsed_body": parsed_body,
            "query": dict(request.query_params),
            "path_param": fixture_id,
            "fixture_header": request.headers.get("x-arcis-fixture"),
            "cookie": request.cookies.get("arcis_note"),
        }

    return TestClient(app)


@pytest.mark.parametrize("fixture", _FIXTURES, ids=lambda fixture: fixture["name"])
def test_shared_dry_run_fixture_reaches_fastapi_unchanged(fixture):
    assert fixture["expected_request_unchanged"] is True
    request_fixture = fixture["request"]
    client = _build_preservation_app()
    response = client.post(
        f"/preserve/{quote(request_fixture['path_param'], safe='')}",
        params=request_fixture["query"],
        content=request_fixture["body_raw"].encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-arcis-fixture": request_fixture["headers"]["x-arcis-fixture"],
            "cookie": f"arcis_note={request_fixture['cookies']['arcis_note']}",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "raw_body": request_fixture["body_raw"],
        "parsed_body": json.loads(request_fixture["body_raw"]),
        "query": request_fixture["query"],
        "path_param": request_fixture["path_param"],
        "fixture_header": request_fixture["headers"]["x-arcis-fixture"],
        "cookie": request_fixture["cookies"]["arcis_note"],
    }


def test_fastapi_dry_run_passes_malformed_json_bytes_to_application():
    app = FastAPI()
    app.add_middleware(
        ArcisMiddleware,
        block=True,
        dry_run=True,
        rate_limit=False,
        headers=False,
    )

    @app.post("/raw")
    async def raw(request: Request):
        return Response(content=await request.body(), media_type="application/octet-stream")

    original = b'{"invoice": "unterminated"'
    response = TestClient(app).post(
        "/raw",
        content=original,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200
    assert response.content == original
