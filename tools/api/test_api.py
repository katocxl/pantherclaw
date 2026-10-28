# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

"""Connect JSON conformance against the disposable server started by Go.

The explicit read-only selection keeps property generation from performing
mutations. Every operation first has to succeed with a valid authenticated
request; an all-401 run can never count as assurance.
"""

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests
import schemathesis
from hypothesis import HealthCheck, seed, settings

ROOT = Path(__file__).resolve().parents[2]
BASE = os.environ["PC_API_TEST_URL"]
COOKIE = os.environ["PC_API_TEST_COOKIE"]
parsed = urlsplit(BASE)
if (
    parsed.scheme != "http"
    or parsed.hostname != "127.0.0.1"
    or parsed.path not in ("", "/")
    or parsed.query
    or parsed.fragment
    or parsed.username
    or parsed.password
):
    raise RuntimeError("API assurance requires the disposable loopback server")

READS = {
    "/pantherclaw.v1.AccessService/WhoAmI": {},
    "/pantherclaw.v1.AccessService/ListRoles": {},
    "/pantherclaw.v1.AccessService/ListUsers": {"pageSize": 5},
    "/pantherclaw.v1.TenancyService/ListTeams": {"pageSize": 5},
    "/pantherclaw.v1.TenancyService/ListBusinessUnits": {"pageSize": 5},
    "/pantherclaw.v1.AgentService/ListAgents": {"pageSize": 5},
    "/pantherclaw.v1.EntitlementService/GetEntitlements": {},
    "/pantherclaw.v1.UsageService/ListUsage": {"days": 30},
    "/pantherclaw.v1.DataRequestService/ListDataRequests": {"pageSize": 5},
    "/pantherclaw.v1.ContainmentService/GetKillSwitch": {},
    "/pantherclaw.v1.CoverageService/ListCoverage": {"pageSize": 5},
    "/pantherclaw.v1.OperationsService/GetSummary": {},
    "/pantherclaw.v1.OperationsService/GetWorkQueue": {},
    "/pantherclaw.v1.OperationsService/GetEvidenceStatus": {},
}
HEADERS = {
    "PC-CSRF": "1",
    "Origin": "http://127.0.0.1:8080",
    "Sec-Fetch-Site": "same-origin",
}
raw = json.loads((ROOT / "docs/api/pantherclaw.openapi.json").read_text("utf-8"))
missing = READS.keys() - raw["paths"].keys()
if missing:
    raise RuntimeError(f"generated schema is missing assurance operations: {sorted(missing)}")
raw["paths"] = {path: {"post": raw["paths"][path]["post"]} for path in READS}
raw["servers"] = [{"url": BASE}]
schema = schemathesis.openapi.from_dict(raw)
schema.config.update(base_url=BASE)
schema.config.generation.max_examples = 25
SECRETS = {COOKIE}
# Opaque cursors are server-issued and server-validated; no schema can say
# which strings are valid, so positive cases send none. Negative cases
# keep generating them, and test_opaque_page_tokens_are_strict asserts
# that a made-up token is refused.
OPAQUE_TOKENS = {"pageToken", "page_token"}


def clear_opaque_tokens(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in OPAQUE_TOKENS and isinstance(item, str):
                value[key] = ""
            else:
                clear_opaque_tokens(item)
    elif isinstance(value, list):
        for item in value:
            clear_opaque_tokens(item)


@schemathesis.hook
def before_call(context, case, kwargs):
    if case.meta is not None and case.meta.generation.mode.is_positive:
        clear_opaque_tokens(case.body)


def safe_failure(error, session):
    """Even a failed conformance report must not reveal a rotated cookie."""
    SECRETS.update(session.cookies.values())
    text = str(error)
    for secret in sorted(SECRETS, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    pytest.fail(text, pytrace=False)


@pytest.fixture(scope="session")
def api_session():
    with requests.Session() as session:
        session.trust_env = False
        session.cookies.set("pc_session", COOKIE, domain="127.0.0.1", path="/")
        # Check the real handlers, permissions and serialization, not merely
        # that unauthenticated requests return a documented error shape.
        for path, body in READS.items():
            case = schema[path]["POST"].Case(body=body)
            try:
                response = case.call_and_validate(base_url=BASE, session=session, headers=HEADERS, timeout=10)
            except Exception as error:
                safe_failure(error, session)
            if response.status_code != 200:
                pytest.fail(f"authenticated baseline {path}: HTTP {response.status_code}", pytrace=False)
        yield session


@schema.parametrize()
@seed(130023)
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_read_conformance(case, api_session):
    try:
        response = case.call_and_validate(
            base_url=BASE,
            session=api_session,
            headers=HEADERS,
            timeout=10,
            allow_redirects=False,
        )
        # Generated body/header cases may be refused, but a lost session
        # would otherwise turn this into a misleading all-auth-errors run.
        if response.status_code == 401:
            pytest.fail("authenticated API assurance lost its session", pytrace=False)
    except Exception as error:
        safe_failure(error, api_session)


@pytest.mark.parametrize(
    "path",
    ["/pantherclaw.v1.CoverageService/ListCoverage", "/pantherclaw.v1.AccessService/ListUsers"],
)
def test_opaque_page_tokens_are_strict(path, api_session):
    """A made-up cursor is refused, never treated as a valid page."""
    response = api_session.post(
        BASE + path,
        json={"pageSize": 5, "pageToken": "not-a-token"},
        headers={**HEADERS, "Connect-Protocol-Version": "1"},
        timeout=10,
        allow_redirects=False,
    )
    assert response.status_code == 400, response.status_code
    body = response.json()
    assert body.get("code") == "invalid_argument", body
    assert body.get("message", "").startswith("INVALID_PAGE_TOKEN"), body
