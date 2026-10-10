"""Shared helpers for consistently logging functional-test HTTP traffic."""

import json
import logging
from typing import Any

import pytest
from fastapi.testclient import TestClient

logger = logging.getLogger("functional.http")
PLATFORM_HEADERS = {"X-Dev-Application-Id": "alzando_platform"}
_SENSITIVE_KEYS = {
    "client_secret", "access_token", "refresh_token", "otp", "verification_code",
    "password", "new_password",
}


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Write a functional case heading before its API-call logs."""
    module_title = (item.module.__doc__ or "").strip().splitlines()
    case_title = module_title[0] if module_title else item.name
    logger.info(
        "\n%s\n%s\nTest: %s\n%s",
        "=" * 80,
        case_title,
        item.name,
        "=" * 80,
    )


def _redact(value: Any, parent_key: str | None = None) -> Any:
    """Return a log-safe copy of a response payload."""
    if isinstance(value, dict):
        has_verification_reference = any(
            key.lower() in {"verification_reference", "recovery_reference"}
            for key in value
        )
        return {
            key: (
                "<redacted>"
                if key.lower() in _SENSITIVE_KEYS
                or (
                    key.lower() == "code"
                    and (
                        parent_key in {"verification", "phone_verification"}
                        or has_verification_reference
                    )
                )
                else _redact(item, key.lower())
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, parent_key) for item in value]
    return value


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    """Hide bearer credentials while retaining useful request context in logs."""
    return {
        key: "<redacted>" if key.lower() == "authorization" else value
        for key, value in headers.items()
    }


@pytest.fixture
def http_request():
    """Send a request and log a consistently formatted input/output block."""

    def request(
        client: TestClient,
        method: str,
        path: str,
        *,
        description: str,
        expectations: str,
        json_body: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        auth: tuple[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ):
        request_headers = headers if headers is not None else PLATFORM_HEADERS
        logger.info(
            "\n%s\nAPI CALL: %s %s\nDescription: %s\nExpectations: %s",
            "=" * 80,
            method.upper(),
            path,
            description,
            expectations,
        )
        logger.info(
            "INPUT\nHeaders: %s\nHTTP Basic Auth: %s\nJSON BODY:\n%s\nFORM DATA:\n%s",
            _safe_headers(request_headers),
            {"username": auth[0], "password": "<redacted>"} if auth else None,
            json.dumps(_redact(json_body), indent=2, sort_keys=True, ensure_ascii=False),
            json.dumps(_redact(data), indent=2, sort_keys=True, ensure_ascii=False),
        )
        try:
            response = client.request(
                method, path, headers=request_headers, json=json_body, data=data, auth=auth
            )
        except Exception:
            logger.exception(
                "\n%s\nOUTPUT\nRequest raised", "-" * 24
            )
            raise

        try:
            output = response.json()
        except ValueError:
            output = response.text
        output_body = (
            json.dumps(_redact(output), indent=2, sort_keys=True, ensure_ascii=False)
            if isinstance(output, (dict, list))
            else output
        )
        logger.info(
            "\n%s\nOUTPUT\nStatus code: %s\nJSON BODY:\n%s\n%s",
            "-" * 24,
            response.status_code,
            output_body,
            "=" * 80,
        )
        return response

    return request
