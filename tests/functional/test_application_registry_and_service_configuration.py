"""Functional Test Case F-REG-01: Application registry and service configuration.

Purpose
-------
Verify the platform-operator journey for discovering available services,
registering a confidential application, reading its configuration, updating
its metadata, replacing its enabled service set, and confirming persisted
state through the public API.

Why this test matters
--------------------
Consuming applications depend on the registry to receive a stable application
ID and client credentials, while the service configuration controls which
authentication and authorization features are available to that application.
This test checks both sides of that contract, including the replace semantics
that disable services omitted from a later configuration request.

Preconditions and isolation
---------------------------
The shared ``api`` fixture creates a fresh in-memory SQLite database and a
FastAPI TestClient for each test. The development-only platform identity is
used to exercise management endpoints. The application created here exists
only in that test database and is discarded during fixture teardown.

Steps and expected outcomes
---------------------------
1. Read the service catalogue; expect active service codes in the response.
2. Register a confidential application with Signup, Login, and Token enabled;
   expect an application ID, client ID, generated secret, and derived scopes.
3. Read the application; expect the registration and enabled services to be
   persisted, with no client secret exposed by the detail endpoint.
4. Patch the application name and description; expect the changes to persist.
5. Replace its service configuration with Login and Token; expect Signup to
   become disabled and per-service configuration to be retained.
6. Submit an unknown service code; expect HTTP 422 and no change to the saved
   configuration.

Logging
-------
Every HTTP input and output is logged at INFO level. Sensitive response keys
such as client secrets and access tokens are redacted before logging. Run with
``--log-cli-level=INFO`` to display the logs in the test output.
"""

def test_platform_operator_registers_and_configures_application(api, http_request):
    """Exercise the complete application-registration/configuration journey."""
    client, _, _ = api

    catalogue = http_request(
        client,
        "GET",
        "/api/v1/services",
        description="List the active services available for application configuration.",
        expectations="HTTP 200; the catalogue includes SIGNUP, LOGIN, and TOKEN.",
    )
    assert catalogue.status_code == 200, catalogue.text
    available_services = {
        service["service_code"] for service in catalogue.json()["data"]["services"]
    }
    assert {"SIGNUP", "LOGIN", "TOKEN"} <= available_services

    registration_body = {
        "name": "Functional Registry Application",
        "description": "Created by F-REG-01",
        "application_type": "EXTERNAL",
        "owner": {"organization": "Functional Test Suite"},
        "client_type": "CONFIDENTIAL",
        "configuration": {"enabled_services": ["SIGNUP", "LOGIN", "TOKEN"]},
    }
    registered = http_request(
        client,
        "POST",
        "/api/v1/applications",
        description=(
            "Register a new application, generate its client credentials, and "
            "configure the requested services."
        ),
        expectations=(
            "HTTP 201; response includes an application ID, client ID, generated "
            "client secret, and scopes for SIGNUP, LOGIN, and TOKEN."
        ),
        json_body=registration_body,
    )
    assert registered.status_code == 201, registered.text
    registration = registered.json()["data"]
    application_id = registration["application_id"]
    assert registration["client"]["client_id"].startswith("client_")
    assert registration["client"]["client_secret"].startswith("secret_")
    assert set(registration["client"]["scopes"]) == {
        "authentication:signup",
        "authentication:login",
        "authentication:token",
    }

    details_path = f"/api/v1/applications/{application_id}"
    details = http_request(
        client,
        "GET",
        details_path,
        description="Retrieve the newly registered application and its service settings.",
        expectations="HTTP 200; application metadata and the three enabled services are returned, without exposing the client secret.",
    )
    assert details.status_code == 200, details.text
    detail_data = details.json()["data"]
    assert detail_data["name"] == registration_body["name"]
    assert "client_secret" not in str(detail_data)
    enabled = {
        service["service_code"]
        for service in detail_data["services"]
        if service["enabled"]
    }
    assert enabled == {"SIGNUP", "LOGIN", "TOKEN"}

    patch_body = {
        "name": "Functional Registry Application Updated",
        "description": "Metadata update verified by F-REG-01",
    }
    patched = http_request(
        client,
        "PATCH",
        details_path,
        description="Update the registered application's name and description.",
        expectations="HTTP 200; the response contains the updated name and description.",
        json_body=patch_body,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["data"]["name"] == patch_body["name"]
    assert patched.json()["data"]["description"] == patch_body["description"]

    replacement_body = {
        "services": [
            {
                "service_code": "LOGIN",
                "enabled": True,
                "configuration": {"allow_password": True},
            },
            {
                "service_code": "TOKEN",
                "enabled": True,
                "configuration": {"access_token_ttl_seconds": 300},
            },
        ]
    }
    replacement = http_request(
        client,
        "PUT",
        f"{details_path}/services",
        description=(
            "Replace the application's enabled service set with Login and Token, "
            "including their service-specific configuration."
        ),
        expectations="HTTP 200; two services are updated, and omitted services such as SIGNUP are disabled.",
        json_body=replacement_body,
    )
    assert replacement.status_code == 200, replacement.text
    assert replacement.json()["data"]["services_updated"] == 2

    after_replacement = http_request(
        client,
        "GET",
        details_path,
        description="Verify the updated service enablement and configuration were persisted.",
        expectations="HTTP 200; LOGIN and TOKEN remain enabled with their settings, while SIGNUP is disabled.",
    )
    assert after_replacement.status_code == 200, after_replacement.text
    current_services = {
        service["service_code"]: service
        for service in after_replacement.json()["data"]["services"]
    }
    assert current_services["LOGIN"]["enabled"] is True
    assert current_services["LOGIN"]["configuration"] == {"allow_password": True}
    assert current_services["TOKEN"]["enabled"] is True
    assert current_services["TOKEN"]["configuration"] == {"access_token_ttl_seconds": 300}
    assert current_services["SIGNUP"]["enabled"] is False

    invalid_body = {
        "services": [{"service_code": "NOT_A_SERVICE", "enabled": True}]
    }
    rejected = http_request(
        client,
        "PUT",
        f"{details_path}/services",
        description="Submit an unknown service code and verify that the API rejects it.",
        expectations="HTTP 422 with UNKNOWN_SERVICE; the invalid service is not saved.",
        json_body=invalid_body,
    )
    assert rejected.status_code == 422
    assert rejected.json()["status"] == "UNKNOWN_SERVICE"

    after_rejection = http_request(
        client,
        "GET",
        details_path,
        description="Confirm the rejected update did not change the saved service settings.",
        expectations="HTTP 200; service settings are unchanged from before the rejected request.",
    )
    assert after_rejection.status_code == 200, after_rejection.text
    assert after_rejection.json()["data"]["services"] == after_replacement.json()["data"]["services"]
