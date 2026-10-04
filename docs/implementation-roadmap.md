# Authentication and Authorization Service Roadmap

This roadmap tracks implementation against the 27 API operations in the supplied Alzando Authentication, Authorization & Security V1 design draft. The draft contains unresolved design items; this roadmap records what is implemented and what still requires a deliberate provider or lifecycle choice.

## Current baseline

- The repository is a FastAPI modular monolith with PostgreSQL and Alembic.
- Confidential application clients can obtain short-lived RS256 client-credentials tokens.
- Application-scoped RBAC supports roles, permissions, role-permission assignment, user-role assignment, and authorization checks.
- Application registration and per-application service configuration are implemented and exercised against the running development API. SkillFlow registration and the non-secret application detail read are verified.
- Signup and password login are implemented with application-scoped accounts, Argon2 password hashes, service/scope enforcement, and the three-failure recovery-required rule. The live SkillFlow migration, signup, and successful password login have been verified.
- Password recovery/reset are implemented with one-time HMAC-digested codes, attempt limits, expiry, development-only code display, SMTP delivery configuration, and reset of the failed-login lock. Live recovery, password reset, and subsequent login have been verified.
- Email verification is implemented with application-scoped, expiring, attempt-limited codes and shared SMTP delivery. SkillFlow signup, verification, and subsequent login have been verified live.
- Phone verification is implemented with E.164 validation and application-scoped, expiring, attempt-limited challenges. SkillFlow's combined email/phone verification and post-verification login have been verified live in development; production SMS delivery awaits provider selection.
- Purpose-scoped OTP request and verify APIs are implemented with application service/scope checks, single-use HMAC-digested codes, expiry, attempt limits, resend cooldown, dev-only code responses, and production SMTP email delivery. The SkillFlow development request and verification flow has been exercised live. SMS delivery awaits provider selection. OTP verification returns proof only and does not issue user tokens or mutate account state.
- MFA challenge and verify APIs are implemented by reusing OTP challenges with the `MFA` purpose and the app's `MFA` plus `OTP` services. The SkillFlow email challenge and verification flow has been exercised live in development. Successful password login creates a short-lived, one-time authentication grant; MFA challenges bind to that grant.
- Application-user tokens use short-lived RS256 access JWTs and opaque rotating refresh tokens. Password login creates a five-minute one-time grant; MFA-enabled applications require an MFA proof bound to that grant before exchange. Refresh-token reuse revokes active sessions for the account. Database migrations and API endpoints are implemented; live verification is pending.
- Development-only `X-Dev-Application-Id` identity is not valid in production.

## API catalogue tracking

| # | API | Status |
|---|---|---|
| 1 | `POST /api/v1/applications` | Implemented; SkillFlow registration verified |
| 2 | `GET /api/v1/applications/{application_id}` | Implemented; SkillFlow detail read verified |
| 3 | `PATCH /api/v1/applications/{application_id}` | Implemented; live write check pending |
| 4 | `GET /api/v1/services` | Implemented; catalogue response verified |
| 5 | `PUT /api/v1/applications/{application_id}/services` | Implemented; live write check pending |
| 6 | `POST /api/v1/auth/signup` | Implemented; verified live against SkillFlow |
| 7 | `POST /api/v1/auth/login` | Implemented; verified live against SkillFlow |
| 8 | `POST /api/v1/auth/password/recovery` | Implemented; verified live against SkillFlow |
| 9 | `POST /api/v1/auth/password/reset` | Implemented; reset and subsequent login verified live |
| 10 | `POST /api/v1/auth/verify/email` | Implemented; verified live against SkillFlow |
| 11 | `POST /api/v1/auth/verify/phone` | Implemented; combined email/phone flow verified live in development; production SMS provider open |
| 12 | `POST /api/v1/auth/otp/request` | Implemented; SkillFlow development flow verified live |
| 13 | `POST /api/v1/auth/otp/verify` | Implemented; SkillFlow development flow verified live |
| 14 | `POST /api/v1/auth/mfa/challenge` | Implemented; SkillFlow development flow verified live |
| 15 | `POST /api/v1/auth/mfa/verify` | Implemented; SkillFlow development flow verified live |
| 16 | `POST /api/v1/auth/passkey/register` | Planned |
| 17 | `POST /api/v1/auth/passkey/authenticate` | Planned |
| 18 | `POST /api/v1/auth/social/{provider}` | Planned |
| 19 | `POST /api/v1/tokens` | Implemented; live verification pending |
| 20 | `POST /api/v1/tokens/refresh` | Implemented; live verification pending |
| 21 | `POST /api/v1/tokens/revoke` | Implemented; live verification pending |
| 22 | `POST /api/v1/authorization/roles` | Implemented; manually exercised |
| 23 | `POST /api/v1/authorization/permissions` | Implemented; manually exercised |
| 24 | `PUT /api/v1/authorization/roles/{role_id}/permissions` | Implemented; manually exercised |
| 25 | `PUT /api/v1/authorization/users/{user_reference}/roles` | Implemented; manually exercised |
| 26 | `POST /api/v1/authorization/check` | Implemented; manually exercised for allow and deny |
| 27 | `GET /api/v1/audit/events` | Planned |

The OAuth 2.0 client-credentials token endpoint (`POST /oauth2/token`) is an additional client-authentication endpoint, distinct from the application-user token APIs in rows 19–21.

## Delivery sequence

1. Finish and exercise application registration, update, and service-configuration writes.
2. Apply and live-verify application-scoped signup/login, including isolation, disabled-service/scope rejection, and the three-failure recovery-required rule.
3. Apply and live-verify password recovery/reset and email verification, then live-verify phone verification and select its production SMS provider before enabling it there.
4. Live-verify MFA and application-user access/refresh/revocation tokens.
5. Add passkey and social-login integrations with provider-specific configuration.
6. Add security/audit events and protected event retrieval.
7. Harden production configuration, credential lifecycle, migrations, operational controls, and end-to-end verification.

## Design items to settle during implementation

- Mapping between Alzando's application-scoped `account_reference` and an application's own user reference.
- The initial account mapping uses an Alzando-generated, application-scoped `account_reference`; each consuming app must map it to its own user ID. Revisit this if product requirements need a caller-supplied reference.
- Email delivery uses SMTP; SMS delivery provider and credentials, retries, and operational failure handling remain open.
- Current initial recovery delivery uses SMTP. Provider selection, delivery retries, and operational alerts remain open for production.
- Social-login providers and account-linking policy.
- WebAuthn relying-party/origin settings and supported passkey ceremony behavior.
- Application-user access-token format, refresh-token storage/rotation, and revocation semantics.
- Audit retention, filtering, pagination, and sensitive-field redaction policy.
- Client-secret rotation and revocation operations, including operator recovery procedures.

Do not treat illustrative payloads or proposed enum values in the design draft as final until the corresponding feature's validation and integration choices are implemented.
