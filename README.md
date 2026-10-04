# Alzando Authorization Service

Current foundation: confidential application clients, application registration and service configuration, and application-scoped RBAC. Authentication workflows are planned as later feature slices.

## Architecture and environments

The service starts as a modular monolith. Features share one API process and common request, identity, configuration, and audit boundaries, then are integrated one feature at a time.

```mermaid
flowchart TB
    subgraph Shared[Shared modular service]
        API[FastAPI API]
        CORE[Shared core<br/>Application context · validation · request IDs]
        MODULES[Feature modules<br/>Authorization · Authentication · MFA<br/>Verification · Tokens · Audit]
        CONFIG[Per-application feature configuration]
        API --> CORE --> MODULES
        MODULES --> CONFIG
    end

    subgraph Development[Development environment]
        DCLIENT[Local client / API docs]
        DAPI[Containerized API]
        DDB[(Local PostgreSQL)]
        DIDENTITY[Development-only identity adapter]
        DCLIENT --> DAPI
        DAPI --> DIDENTITY
        DAPI --> DDB
    end

    subgraph Production[Production environment]
        PCLIENT[Consuming applications]
        GATEWAY[HTTPS gateway]
        PAPI[Containerized API]
        PDB[(Managed PostgreSQL)]
        PIDENTITY[OAuth 2.0 client credentials<br/>RS256 access tokens]
        SECRETS[Secrets manager]
        OBS[Logs · metrics · traces]
        PCLIENT --> GATEWAY --> PAPI
        PAPI --> PIDENTITY
        PAPI --> PDB
        PAPI --> SECRETS
        PAPI --> OBS
    end

    Shared -. same code, environment-specific configuration .-> Development
    Shared -. same code, hardened deployment configuration .-> Production
```

## Development stack

- Python 3.12, FastAPI, and Pydantic
- PostgreSQL 16, SQLAlchemy, and Alembic migrations
- Docker Compose for a local API and database

Development uses PostgreSQL to match the production database family. Confidential back-end applications authenticate with OAuth 2.0 client credentials. The service issues short-lived RS256 access tokens and derives the application identity and granted scopes from validated token claims. In development only, `X-Dev-Application-Id` remains available for quick API exploration. Production ignores that header. Public clients can be registered without a secret; their login/token flow is a later feature.

## Start the development stack

Install Docker Desktop, then run from the repository root:

```bash
docker compose up --build
```

The API is available at `http://localhost:8000`; interactive API docs are at `http://localhost:8000/docs`. Startup applies checked-in Alembic migrations. Local PostgreSQL data is kept in the `postgres_data` Docker volume. After pulling code that changes dependencies or migrations, rebuild with `docker compose up --build`.

For local API calls, include a development-only application context header:

```http
X-Dev-Application-Id: <registered_application_id>
```

Register the application first; the migration preserves older `app_local` development data if present. Do not use development credentials or this header in production.

In development, register an application with the development-only platform identity:

```powershell
$operatorHeaders = @{ "X-Dev-Application-Id" = "alzando_platform" }
$registration = @{
  name = "SkillFlow"
  description = "Learning platform"
  application_type = "ALZANDO_OWNED"
  owner = @{ organization = "Alzando" }
  client_type = "CONFIDENTIAL"
  configuration = @{ enabled_services = @("AUTHORIZATION") }
} | ConvertTo-Json -Depth 5
$app = Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/v1/applications -Headers $operatorHeaders -ContentType "application/json" -Body $registration
$app.data
```

The response includes an Alzando-generated application ID, client ID, and (for confidential clients) a client secret shown once. Save the secret securely; PostgreSQL stores only its Argon2 hash. The initial client receives runtime scopes corresponding to the enabled services (Authorization, Signup, and Login are currently supported).

In production, application registration and service configuration require a platform-operator client. Provision one from the trusted deployment environment:

```powershell
docker compose exec api python -m alzando_authorization.cli create-platform-admin
```

This privileged client is assigned to the reserved `alzando_platform` context and receives only `platform:manage`. Exchange its credentials at `/oauth2/token` with `scope=platform:manage`, then send its Bearer token to registry/configuration APIs. Do not expose its secret to consuming applications. In local development, use the `X-Dev-Application-Id: alzando_platform` shortcut shown above.

Provision a separate application-scoped client for RBAC administration when needed. Replace `<application_id>` with the ID returned by registration:

```powershell
docker compose exec api python -m alzando_authorization.cli create-client --application-id YOUR_APPLICATION_ID --scope authorization:manage --scope authorization:check
```

Keep the management client credentials on trusted backend/admin infrastructure. Do not give `authorization:manage` to an ordinary application runtime client unless that runtime must administer roles.

Request an application token from PowerShell, replacing the values with its registration output:

```powershell
$pair = "CLIENT_ID:CLIENT_SECRET"
$basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
$tokenResponse = Invoke-RestMethod -Method Post -Uri http://localhost:8000/oauth2/token -Headers @{ Authorization = "Basic $basic" } -ContentType "application/x-www-form-urlencoded" -Body @{ grant_type = "client_credentials"; scope = "authorization:check" }
$token = $tokenResponse.access_token
```

Send `Authorization: Bearer $token` with API calls. Role, permission, and assignment endpoints require `authorization:manage`; the decision endpoint requires `authorization:check`. Tokens for Authorization are rejected while that service is disabled for the application.

## Implemented API surface

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/applications` | Register an application and its initial client |
| `GET` | `/api/v1/applications/{application_id}` | Retrieve application, client metadata, and service configuration |
| `PATCH` | `/api/v1/applications/{application_id}` | Update application name, description, owner, or status |
| `GET` | `/api/v1/services` | List the service catalogue |
| `PUT` | `/api/v1/applications/{application_id}/services` | Replace application service configuration |
| `POST` | `/api/v1/auth/signup` | Create an application-scoped password account |
| `POST` | `/api/v1/auth/login` | Authenticate an application-scoped password account |
| `POST` | `/api/v1/auth/password/recovery` | Start account password recovery |
| `POST` | `/api/v1/auth/password/reset` | Verify a recovery code and set a new password |
| `POST` | `/api/v1/auth/verify/email` | Verify an account email address |
| `POST` | `/api/v1/auth/verify/phone` | Verify an account phone number |
| `POST` | `/api/v1/auth/otp/request` | Request a purpose-scoped one-time password |
| `POST` | `/api/v1/auth/otp/verify` | Verify a one-time password challenge |
| `POST` | `/api/v1/auth/mfa/challenge` | Start an MFA one-time-password challenge |
| `POST` | `/api/v1/auth/mfa/verify` | Verify an MFA challenge |
| `POST` | `/api/v1/tokens` | Exchange a successful authentication grant for user tokens |
| `POST` | `/api/v1/tokens/refresh` | Rotate a user refresh token |
| `POST` | `/api/v1/tokens/revoke` | Revoke a user refresh-token session |
| `POST` | `/api/v1/authorization/roles` | Create an application-scoped role |
| `POST` | `/api/v1/authorization/permissions` | Create an application-scoped permission |
| `PUT` | `/api/v1/authorization/roles/{role_id}/permissions` | Replace a role's complete permission set |
| `PUT` | `/api/v1/authorization/users/{user_reference}/roles` | Replace a user's complete role set |
| `POST` | `/api/v1/authorization/check` | Return an `ALLOWED` or `DENIED` RBAC decision |
| `POST` | `/oauth2/token` | Issue a short-lived access token to a confidential client |

Application registry and service-configuration APIs require `platform:manage`. Authorization APIs require the Authorization service to be enabled for the registered application and enforce application scopes. Relationship tables use composite foreign keys to prevent cross-application role and permission links. Empty arrays on either RBAC relationship `PUT` endpoint clear assignments. Resource context is accepted and echoed, but V1 does not evaluate ownership or resource-level rules.

Signup and login require application credentials with `authentication:signup` and `authentication:login`, respectively, and the matching service must be enabled. Signup accepts email, optional phone/display name, and a password of 12–128 characters. Email is normalized to lowercase; passwords are stored as Argon2 hashes. Accounts and generated `account_reference` values are application-scoped. The consuming application should store the mapping to its own user ID. A successful login creates a short-lived, one-time authentication grant; `/api/v1/tokens` exchanges it for user tokens. When MFA is enabled, login returns `MFA_REQUIRED`, and the grant must pass the MFA challenge before exchange. Three consecutive incorrect passwords put an account into `RECOVERY_REQUIRED`; successful password authentication resets the counter. If email or phone verification is enabled, signup creates pending accounts and login returns `VERIFICATION_REQUIRED` until required channels are verified.

Password recovery and reset require `authentication:recovery` and the enabled `PASSWORD_RECOVERY` service. Recovery responses are account-enumeration resistant and do not include challenge material in production. Codes are HMAC-digested, expire after five minutes by default, allow five attempts, are single-use, and are limited to one request per account per minute by default. In development, the code and recovery reference are returned for local testing. In production, set `CHALLENGE_HMAC_SECRET` (at least 32 characters), `SMTP_HOST`, and `SMTP_FROM_EMAIL`; configure SMTP credentials if required. Delivery runs after the response and delivery failures are logged without recovery values or email addresses. A successful reset sets a new Argon2 password and clears the failed-login lock. Password reset does not issue a user access token.

When Email Verification is enabled, Signup creates a pending account and sends a short-lived email code. The signup response returns the verification reference; only development responses include the code. `POST /api/v1/auth/verify/email` requires the `authentication:verify` scope and enabled `EMAIL_VERIFICATION` service. Codes expire after ten minutes by default, allow five attempts, and are single-use. Email uses the same SMTP configuration as recovery.

When Phone Verification is enabled, Signup requires a phone number in E.164 form (for example `+14155550123`) and creates a second pending verification challenge. In development, the API returns the code for local testing; production SMS delivery is intentionally unavailable until an SMS provider is selected and configured. `POST /api/v1/auth/verify/phone` requires `authentication:verify_phone` and the `PHONE_VERIFICATION` service. If both email and phone verification are enabled, the account becomes active only after both channels are verified.

Generic OTP requests require the `OTP` service and `authentication:otp` client scope. Requests include an application-scoped account reference, purpose (`LOGIN`, `VERIFICATION`, or `RECOVERY`), and channel (`EMAIL` or `SMS`). The service also checks the corresponding application service: `LOGIN`, `EMAIL_VERIFICATION` or `PHONE_VERIFICATION`, or `PASSWORD_RECOVERY`. MFA codes must use the grant-bound MFA endpoints. Challenges expire after five minutes by default, permit five code attempts, and enforce a one-minute resend delay per account, purpose, and channel. In development, the response includes the code; in production, email codes are sent through configured SMTP and SMS requests return `SERVICE_UNAVAILABLE` until an SMS provider is configured. Unknown account references receive a generic challenge response to reduce account enumeration. OTP verification returns proof metadata only; it does not create a user session, issue a token, change account verification state, or reset a password. Use the dedicated login, verify, and recovery endpoints for those workflows.

Provision a separate application client with the OTP scope after enabling `OTP` and the purpose-specific service(s) in the application's service configuration:

```powershell
docker compose exec api python -m alzando_authorization.cli create-client --application-id YOUR_APPLICATION_ID --scope authentication:otp
```

The MFA challenge endpoints reuse the OTP challenge store and delivery flow with purpose `MFA`. Enable both the `MFA` and `OTP` services for the application. Enabling MFA currently requires it for all password logins in that application. A successful password login returns a short-lived `authentication_reference`; when MFA is enabled, its status is `MFA_REQUIRED`. Send that reference to `/api/v1/auth/mfa/challenge`, then verify the resulting code at `/api/v1/auth/mfa/verify`. MFA challenges are bound to that grant, require a registered account with a verified destination channel, and use email delivery in production; SMS remains development-only until an SMS provider is configured. After verification, exchange the grant at `POST /api/v1/tokens`. Login without MFA can exchange its grant directly.

Provision a client that needs the explicit MFA challenge endpoints with:

```powershell
docker compose exec api python -m alzando_authorization.cli create-client --application-id YOUR_APPLICATION_ID --scope authentication:mfa --scope authentication:login --scope authentication:token
```

Application-user tokens are distinct from OAuth client-credentials tokens. The user access token is an RS256 JWT with `token_use=user_access`, a five-minute default lifetime, the application ID, account reference, session ID, and authentication methods. The refresh token is an opaque random value; only its SHA-256 digest is stored. Refresh rotates the token, and reuse of a rotated token revokes all active sessions for that account. Revocation invalidates the refresh session; an already issued access token remains valid until its short expiry. The `authentication_reference` expires after five minutes by default and can be exchanged only once. The app client must have `authentication:token` and the application's `TOKEN` service enabled. Client-credentials access tokens continue to use `/oauth2/token`.

Enable `TOKEN` on the application and provision a confidential backend client with `authentication:login`, `authentication:token`, and `authentication:mfa` when MFA is enabled. In local development, `X-Dev-Application-Id` can be used for manual API calls.

To provision an application client for the implemented authentication APIs, enable Signup/Login through the platform configuration API, then create a separate confidential client with the needed scopes:

```powershell
docker compose exec api python -m alzando_authorization.cli create-client --application-id YOUR_APPLICATION_ID --scope authentication:signup --scope authentication:login --scope authentication:token
```

Add `--scope authentication:recovery` when the application's client also needs password recovery.

Save the generated secret securely. Do not paste it into source control or chat. Each scope is rejected at token issuance if its service is disabled for that application.

## Production deployment requirements

- Set `TOKEN_ISSUER`, `TOKEN_AUDIENCE`, and `JWT_PRIVATE_KEY_FILE` to production values. Mount the signing key from a secret manager; never commit it to Git. `JWT_PUBLIC_KEY_FILE` can supply the verification key separately.
- Use managed PostgreSQL, secret storage, TLS, and operational monitoring.
- Public-client authentication, passkeys, social login, and audit-event APIs remain planned feature slices. OTP and MFA challenge flows are verified in development; application-user token endpoints are implemented and await live verification.
- The accepted application-type values and detailed per-service configuration schemas are initial V1 choices and should be reviewed against product requirements.

## API response envelope

Successes and service errors use the working response shape from the Alzando specification: `success`, `status`, `data`, `error`, and `request_id`. The exact public contract and HTTP mappings remain subject to the specification's open design decisions.
