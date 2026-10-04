from alzando_authorization.models import Application, ApplicationService


def _enable_authorization(sessions, app_id="app_pytest"):
    with sessions() as db:
        service = db.get(ApplicationService, (app_id, "AUTHORIZATION"))
        service.enabled = True
        db.commit()


def _create_second_application(sessions):
    with sessions() as db:
        db.add(Application(
            application_id="app_other",
            name="Other Application",
            application_type="EXTERNAL",
            owner={},
            status="ACTIVE",
        ))
        db.flush()
        db.add(ApplicationService(
            application_id="app_other", service_code="AUTHORIZATION", enabled=True, configuration={}
        ))
        db.commit()


def test_role_permission_assignment_and_authorization_decision(api):
    client, sessions, _ = api
    _enable_authorization(sessions)
    headers = {"X-Dev-Application-Id": "app_pytest"}
    role_response = client.post(
        "/api/v1/authorization/roles", headers=headers,
        json={"name": "editor", "description": "Can edit lessons"},
    )
    permission_response = client.post(
        "/api/v1/authorization/permissions", headers=headers,
        json={"key": "lesson.edit", "resource": "lesson", "action": "edit"},
    )
    assert role_response.status_code == 201, role_response.text
    assert permission_response.status_code == 201, permission_response.text
    role_id = role_response.json()["data"]["role_id"]
    permission_id = permission_response.json()["data"]["permission_id"]

    role_update = client.put(
        f"/api/v1/authorization/roles/{role_id}/permissions", headers=headers,
        json={"permission_ids": [permission_id]},
    )
    user_update = client.put(
        "/api/v1/authorization/users/user-42/roles", headers=headers,
        json={"role_ids": [role_id]},
    )
    assert role_update.status_code == 200
    assert role_update.json()["data"]["permission_count"] == 1
    assert user_update.status_code == 200

    allowed = client.post(
        "/api/v1/authorization/check", headers=headers,
        json={"user_reference": "user-42", "permission": "lesson.edit",
              "resource": {"type": "lesson", "id": "lesson-1"}},
    )
    denied = client.post(
        "/api/v1/authorization/check", headers=headers,
        json={"user_reference": "user-42", "permission": "lesson.delete"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["data"]["decision"] == "ALLOWED"
    assert denied.status_code == 200
    assert denied.json()["data"]["decision"] == "DENIED"


def test_empty_relationship_replacements_clear_authorization(api):
    client, sessions, _ = api
    _enable_authorization(sessions)
    headers = {"X-Dev-Application-Id": "app_pytest"}
    role_id = client.post(
        "/api/v1/authorization/roles", headers=headers, json={"name": "reader"}
    ).json()["data"]["role_id"]
    permission_id = client.post(
        "/api/v1/authorization/permissions", headers=headers,
        json={"key": "course.read", "resource": "course", "action": "read"},
    ).json()["data"]["permission_id"]
    client.put(
        f"/api/v1/authorization/roles/{role_id}/permissions", headers=headers,
        json={"permission_ids": [permission_id]},
    )
    client.put(
        "/api/v1/authorization/users/user-1/roles", headers=headers,
        json={"role_ids": [role_id]},
    )

    cleared_permissions = client.put(
        f"/api/v1/authorization/roles/{role_id}/permissions", headers=headers,
        json={"permission_ids": []},
    )
    cleared_roles = client.put(
        "/api/v1/authorization/users/user-1/roles", headers=headers,
        json={"role_ids": []},
    )
    decision = client.post(
        "/api/v1/authorization/check", headers=headers,
        json={"user_reference": "user-1", "permission": "course.read"},
    )
    assert cleared_permissions.json()["data"]["permission_count"] == 0
    assert cleared_roles.json()["data"]["role_count"] == 0
    assert decision.json()["data"]["decision"] == "DENIED"


def test_rbac_rejects_cross_application_role_and_permission_references(api):
    client, sessions, _ = api
    _enable_authorization(sessions)
    _create_second_application(sessions)
    app_headers = {"X-Dev-Application-Id": "app_pytest"}
    other_headers = {"X-Dev-Application-Id": "app_other"}
    other_role_id = client.post(
        "/api/v1/authorization/roles", headers=other_headers, json={"name": "other-role"}
    ).json()["data"]["role_id"]
    other_permission_id = client.post(
        "/api/v1/authorization/permissions", headers=other_headers,
        json={"key": "other.read", "resource": "other", "action": "read"},
    ).json()["data"]["permission_id"]

    role_assignment = client.put(
        "/api/v1/authorization/users/user-1/roles", headers=app_headers,
        json={"role_ids": [other_role_id]},
    )
    local_role = client.post(
        "/api/v1/authorization/roles", headers=app_headers, json={"name": "local-role"}
    ).json()["data"]["role_id"]
    permission_assignment = client.put(
        f"/api/v1/authorization/roles/{local_role}/permissions",
        headers=app_headers,
        json={"permission_ids": [other_permission_id]},
    )
    assert role_assignment.status_code == 422
    assert role_assignment.json()["status"] == "REFERENCE_NOT_FOUND"
    assert permission_assignment.status_code == 422
    assert permission_assignment.json()["status"] == "REFERENCE_NOT_FOUND"


def test_rbac_requires_enabled_authorization_service(api):
    client, _, _ = api
    response = client.post(
        "/api/v1/authorization/roles",
        headers={"X-Dev-Application-Id": "app_pytest"},
        json={"name": "blocked"},
    )
    assert response.status_code == 403
    assert response.json()["status"] == "SERVICE_NOT_ENABLED"
