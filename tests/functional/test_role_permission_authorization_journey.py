"""Functional Test Case F-AUTHZ-01: Role and permission authorization journey.

Purpose
-------
Create an application role and permission, associate the permission with the
role, assign the role to a user, and ask the authorization API to decide
whether that user may perform the corresponding action.

Why this test matters
--------------------
This is the normal RBAC administration path: administrators define reusable
permissions, grant them to roles, assign roles to users, and application code
checks access before allowing an operation. A second check confirms that an
ungranted permission is denied.

Preconditions and isolation
---------------------------
The shared ``api`` fixture creates a fresh in-memory SQLite database and a
FastAPI TestClient. The AUTHORIZATION service is enabled for the isolated
``app_pytest`` application. All roles, permissions, and assignments are
discarded after the test.

Steps and expected outcomes
---------------------------
1. Create an editor role and a lesson-edit permission.
2. Attach the permission to the role and assign that role to a user.
3. Check lesson.edit; expect ALLOWED.
4. Check lesson.delete; expect DENIED.

Logging
-------
Every HTTP call logs its API description, expectations, input, and response
using the shared functional-test logger.
"""


def test_role_permission_assignment_produces_allowed_and_denied_decisions(
    api, enable_services, http_request
):
    """Confirm RBAC associations drive the authorization decision endpoint."""
    client, _, _ = api
    enable_services("AUTHORIZATION")
    headers = {"X-Dev-Application-Id": "app_pytest"}

    role = http_request(
        client,
        "POST",
        "/api/v1/authorization/roles",
        description="Create an editor role for the test application.",
        expectations="HTTP 201; the response returns the new role ID and name.",
        json_body={"name": "functional-editor", "description": "Can edit lessons"},
        headers=headers,
    )
    assert role.status_code == 201, role.text
    role_id = role.json()["data"]["role_id"]

    permission = http_request(
        client,
        "POST",
        "/api/v1/authorization/permissions",
        description="Create a permission allowing a user to edit lessons.",
        expectations="HTTP 201; the response returns the lesson.edit permission ID and attributes.",
        json_body={
            "key": "lesson.edit",
            "description": "Edit a lesson",
            "resource": "lesson",
            "action": "edit",
        },
        headers=headers,
    )
    assert permission.status_code == 201, permission.text
    permission_id = permission.json()["data"]["permission_id"]

    role_permissions = http_request(
        client,
        "PUT",
        f"/api/v1/authorization/roles/{role_id}/permissions",
        description="Grant the lesson.edit permission to the editor role.",
        expectations="HTTP 200; one permission is associated with the role.",
        json_body={"permission_ids": [permission_id]},
        headers=headers,
    )
    assert role_permissions.status_code == 200, role_permissions.text
    assert role_permissions.json()["data"]["permission_count"] == 1

    user_roles = http_request(
        client,
        "PUT",
        "/api/v1/authorization/users/functional-user/roles",
        description="Assign the editor role to the functional user.",
        expectations="HTTP 200; one role is associated with the user.",
        json_body={"role_ids": [role_id]},
        headers=headers,
    )
    assert user_roles.status_code == 200, user_roles.text
    assert user_roles.json()["data"]["role_count"] == 1

    allowed = http_request(
        client,
        "POST",
        "/api/v1/authorization/check",
        description="Check whether the user can edit a specific lesson.",
        expectations="HTTP 200; decision is ALLOWED because the user has the editor role.",
        json_body={
            "user_reference": "functional-user",
            "permission": "lesson.edit",
            "resource": {"type": "lesson", "id": "lesson-1001"},
        },
        headers=headers,
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["data"]["decision"] == "ALLOWED"

    denied = http_request(
        client,
        "POST",
        "/api/v1/authorization/check",
        description="Check whether the same user can delete a lesson without that permission.",
        expectations="HTTP 200; decision is DENIED because no lesson.delete permission is assigned.",
        json_body={
            "user_reference": "functional-user",
            "permission": "lesson.delete",
            "resource": {"type": "lesson", "id": "lesson-1001"},
        },
        headers=headers,
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["data"]["decision"] == "DENIED"
