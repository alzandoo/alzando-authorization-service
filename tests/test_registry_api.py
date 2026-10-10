import alzando_authorization.registry as registry
from types import SimpleNamespace
from alzando_authorization.models import Application, ApplicationService


PLATFORM_HEADER = {"X-Dev-Application-Id": "alzando_platform"}


def test_service_catalogue_and_application_registration(api):
    client, sessions, _ = api
    catalogue = client.get("/api/v1/services", headers=PLATFORM_HEADER)
    assert catalogue.status_code == 200
    service_codes = {item["service_code"] for item in catalogue.json()["data"]["services"]}
    # APP-01: Verify that the service catalogue contains all required services.
    assert {"SIGNUP", "LOGIN", "TOKEN", "AUTHORIZATION"} <= service_codes

    response = client.post(
        "/api/v1/applications",
        headers=PLATFORM_HEADER,
        json={
            "name": "Registry Test App",
            "application_type": "EXTERNAL",
            "client_type": "CONFIDENTIAL",
            "configuration": {"enabled_services": ["SIGNUP", "LOGIN", "TOKEN"]},
        },
    )
    assert response.status_code == 201, response.text
    registered = response.json()["data"]
    assert registered["client"]["client_secret"].startswith("secret_")
    assert set(registered["client"]["scopes"]) == {
        "authentication:signup", "authentication:login", "authentication:token"
    }

    details = client.get(
        f"/api/v1/applications/{registered['application_id']}", headers=PLATFORM_HEADER
    )
    assert details.status_code == 200
    assert "client_secret" not in str(details.json())
    assert {row["service_code"] for row in details.json()["data"]["services"]
            if row["enabled"]} == {"SIGNUP", "LOGIN", "TOKEN"}
    with sessions() as db:
        assert db.get(Application, registered["application_id"]).status == "ACTIVE"


def test_public_application_registration_does_not_return_a_secret(api):
    client, _, _ = api
    response = client.post(
        "/api/v1/applications",
        headers=PLATFORM_HEADER,
        json={
            "name": "Public Test App",
            "application_type": "EXTERNAL",
            "client_type": "PUBLIC",
            "configuration": {"enabled_services": ["LOGIN"]},
        },
    )
    assert response.status_code == 201, response.text
    data = response.json()["data"]
    assert data["client"]["client_type"] == "PUBLIC"
    assert data["client"]["client_secret"] is None
    assert data["client"]["scopes"] == ["authentication:login"]


def test_registration_rejects_unknown_or_duplicate_services(api):
    client, _, _ = api
    base = {
        "name": "Invalid Test App",
        "application_type": "EXTERNAL",
        "client_type": "CONFIDENTIAL",
    }
    unknown = client.post(
        "/api/v1/applications", headers=PLATFORM_HEADER,
        json={**base, "configuration": {"enabled_services": ["NOT_A_SERVICE"]}},
    )
    duplicate = client.post(
        "/api/v1/applications", headers=PLATFORM_HEADER,
        json={**base, "configuration": {"enabled_services": ["LOGIN", "login"]}},
    )
    assert unknown.status_code == 422
    assert unknown.json()["status"] == "UNKNOWN_SERVICE"
    assert duplicate.status_code == 422
    assert duplicate.json()["status"] == "INVALID_REQUEST"


def test_application_patch_and_service_replacement(api):
    client, sessions, _ = api
    app_id = "app_pytest"
    patched = client.patch(
        f"/api/v1/applications/{app_id}", headers=PLATFORM_HEADER,
        json={"name": "Updated Test App", "description": "updated"},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["data"]["name"] == "Updated Test App"

    updated = client.put(
        f"/api/v1/applications/{app_id}/services", headers=PLATFORM_HEADER,
        json={"services": [
            {"service_code": "LOGIN", "enabled": True, "configuration": {"mfa": False}},
            {"service_code": "TOKEN", "enabled": True},
        ]},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["data"]["services_updated"] == 2
    with sessions() as db:
        login = db.get(ApplicationService, (app_id, "LOGIN"))
        token = db.get(ApplicationService, (app_id, "TOKEN"))
        signup = db.get(ApplicationService, (app_id, "SIGNUP"))
        assert login.enabled is True
        assert login.configuration == {"mfa": False}
        assert token.enabled is True
        assert signup.enabled is False


def test_registry_not_found_validation_and_platform_access(api):
    client, _, _ = api
    missing = client.get("/api/v1/applications/missing", headers=PLATFORM_HEADER)
    empty_patch = client.patch(
        "/api/v1/applications/app_pytest", headers=PLATFORM_HEADER, json={}
    )
    unknown_service = client.put(
        "/api/v1/applications/app_pytest/services", headers=PLATFORM_HEADER,
        json={"services": [{"service_code": "UNKNOWN", "enabled": True}]},
    )
    no_platform_context = client.get("/api/v1/services", headers={"X-Dev-Application-Id": "app_pytest"})
    assert missing.status_code == 404
    assert missing.json()["status"] == "APPLICATION_NOT_FOUND"
    assert empty_patch.status_code == 422
    assert empty_patch.json()["status"] == "INVALID_REQUEST"
    assert unknown_service.status_code == 422
    assert unknown_service.json()["status"] == "UNKNOWN_SERVICE"
    assert no_platform_context.status_code == 401

# APP-02: Verify that duplicate application IDs are rejected with HTTP 409.
def test_registration_rejects_duplicate_application_id(api, monkeypatch):
    client, sessions, _ = api
    # Patch the token generator to produce a duplicate application_id
    monkeypatch.setattr(registry, "secrets", SimpleNamespace(token_urlsafe=lambda n: "pytest"))
    
    response = client.post(
        "/api/v1/applications",
        headers=PLATFORM_HEADER,
        json={
            "name": "Duplicate ID App",
            "application_type": "EXTERNAL",
            "client_type": "CONFIDENTIAL",
            "configuration": {"enabled_services": ["LOGIN"]},
        },
    )
    assert response.status_code == 409, response.text
    assert response.json()["status"] == "APPLICATION_REGISTRATION_FAILED"
