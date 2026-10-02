# Authentication and Authorization Service Roadmap

This roadmap tracks implementation against the 27 API operations in the supplied Alzando Authentication, Authorization & Security V1 design draft. The draft contains unresolved design items; this roadmap records what is implemented and what still requires a deliberate provider or lifecycle choice.

## Current baseline

- The repository is a FastAPI modular monolith with PostgreSQL and Alembic.
- Confidential application clients can obtain short-lived RS256 client-credentials tokens.
- Application-scoped RBAC supports roles, permissions, role-permission assignment, user-role assignment, and authorization checks.
- Application registration and per-application service configuration have been added locally; the migration and service catalogue have been exercised against the running development API. The registration write path still needs an end-to-end check.
- Development-only `X-Dev-Application-Id` identity is not valid in production.

## API catalogue tracking

| # | API | Status |
|---|---|---|
| 1 | `POST /api/v1/applications` | Implemented; live write check pending |
| 2 | `GET /api/v1/applications/{application_id}` | Implemented; legacy application read verified |
| 3 | `PATCH /api/v1/applications/{application_id}` | Implemented; live write check pending |
| 4 | `GET /api/v1/services` | Implemented; catalogue response verified |
| 5 | `PUT /api/v1/applications/{application_id}/services` | Implemented; live write check pending |
| 6 | `POST /api/v1/auth/signup` | Planned |
| 7 | `POST /api/v1/auth/login` | Planned |
| 8 | `POST /api/v1/auth/password/recovery` | Planned |
| 9 | `POST /api/v1/auth/password/reset` | Planned |
| 10 | `POST /api/v1/auth/verify/email` | Planned |
| 11 | `POST /api/v1/auth/verify/phone` | Planned |
| 12 | `POST /api/v1/auth/otp/request` | Planned |
| 13 | `POST /api/v1/auth/otp/verify` | Planned |
| 14 | `POST /api/v1/auth/mfa/challenge` | Planned |
| 15 | `POST /api/v1/auth/mfa/verify` | Planned |
| 16 | `POST /api/v1/auth/passkey/register` | Planned |
| 17 | `POST /api/v1/auth/passkey/authenticate` | Planned |
| 18 | `POST /api/v1/auth/social/{provider}` | Planned |
| 19 | `POST /api/v1/tokens` | Planned |
| 20 | `POST /api/v1/tokens/refresh` | Planned |
| 21 | `POST /api/v1/tokens/revoke` | Planned |
| 22 | `POST /api/v1/authorization/roles` | Implemented; manually exercised |
| 23 | `POST /api/v1/authorization/permissions` | Implemented; manually exercised |
| 24 | `PUT /api/v1/authorization/roles/{role_id}/permissions` | Implemented; manually exercised |
| 25 | `PUT /api/v1/authorization/users/{user_reference}/roles` | Implemented; manually exercised |
| 26 | `POST /api/v1/authorization/check` | Implemented; manually exercised for allow and deny |
| 27 | `GET /api/v1/audit/events` | Planned |

The OAuth 2.0 client-credentials token endpoint (`POST /oauth2/token`) is an additional client-authentication endpoint, distinct from the application-user token APIs in rows 19–21.

## Delivery sequence

1. Finish and exercise application registration, update, and service-configuration writes.
2. Add application-scoped authentication accounts, signup, password login, and the three-failure recovery-required rule.
3. Add verification and challenge foundations, then email/phone verification, password recovery/reset, and OTP.
4. Add MFA and application-user access/refresh/revocation tokens.
5. Add passkey and social-login integrations with provider-specific configuration.
6. Add security/audit events and protected event retrieval.
7. Harden production configuration, credential lifecycle, migrations, operational controls, and end-to-end verification.

## Design items to settle during implementation

- Mapping between Alzando's application-scoped `account_reference` and an application's own user reference.
- Email and SMS delivery providers, provider credentials, retries, and development delivery behavior.
- Social-login providers and account-linking policy.
- WebAuthn relying-party/origin settings and supported passkey ceremony behavior.
- Application-user access-token format, refresh-token storage/rotation, and revocation semantics.
- Audit retention, filtering, pagination, and sensitive-field redaction policy.
- Client-secret rotation and revocation operations, including operator recovery procedures.

Do not treat illustrative payloads or proposed enum values in the design draft as final until the corresponding feature's validation and integration choices are implemented.
