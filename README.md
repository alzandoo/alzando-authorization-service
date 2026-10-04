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
| `POST` | `/api/v1/authorization/roles` | Create an application-scoped role |
| `POST` | `/api/v1/authorization/permissions` | Create an application-scoped permission |
| `PUT` | `/api/v1/authorization/roles/{role_id}/permissions` | Replace a role's complete permission set |
| `PUT` | `/api/v1/authorization/users/{user_reference}/roles` | Replace a user's complete role set |
| `POST` | `/api/v1/authorization/check` | Return an `ALLOWED` or `DENIED` RBAC decision |
| `POST` | `/oauth2/token` | Issue a short-lived access token to a confidential client |

Application registry and service-configuration APIs require `platform:manage`. Authorization APIs require the Authorization service to be enabled for the registered application and enforce application scopes. Relationship tables use composite foreign keys to prevent cross-application role and permission links. Empty arrays on either RBAC relationship `PUT` endpoint clear assignments. Resource context is accepted and echoed, but V1 does not evaluate ownership or resource-level rules.

Signup and login require application credentials with `authentication:signup` and `authentication:login`, respectively, and the matching service must be enabled. Signup accepts email, optional phone/display name, and a password of 12–128 characters. Email is normalized to lowercase; passwords are stored as Argon2 hashes. Accounts and generated `account_reference` values are application-scoped. The consuming application should store the mapping to its own user ID. Login accepts email/password and returns an authentication state; application-user access/refresh tokens are not included until the Token Services APIs are implemented. Three consecutive incorrect passwords put an account into `RECOVERY_REQUIRED`; successful password authentication resets the counter. If Email Verification is enabled, signup/login return `VERIFICATION_REQUIRED`; challenge delivery and verification endpoints are a later feature slice.

Password recovery and reset require `authentication:recovery` and the enabled `PASSWORD_RECOVERY` service. Recovery responses are account-enumeration resistant and do not include challenge material in production. Codes are HMAC-digested, expire after five minutes by default, allow five attempts, are single-use, and are limited to one request per account per minute by default. In development, the code and recovery reference are returned for local testing. In production, set `CHALLENGE_HMAC_SECRET` (at least 32 characters), `SMTP_HOST`, and `SMTP_FROM_EMAIL`; configure SMTP credentials if required. Delivery runs after the response and delivery failures are logged without recovery values or email addresses. A successful reset sets a new Argon2 password and clears the failed-login lock. Password reset does not issue a user access token.

When Email Verification is enabled, Signup creates a pending account and sends a short-lived email code. The signup response returns the verification reference; only development responses include the code. `POST /api/v1/auth/verify/email` requires the `authentication:verify` scope and enabled `EMAIL_VERIFICATION` service. Codes expire after ten minutes by default, allow five attempts, and are single-use. Email uses the same SMTP configuration as recovery.

When Phone Verification is enabled, Signup requires a phone number in E.164 form (for example `+14155550123`) and creates a second pending verification challenge. In development, the API returns the code for local testing; production SMS delivery is intentionally unavailable until an SMS provider is selected and configured. `POST /api/v1/auth/verify/phone` requires `authentication:verify_phone` and the `PHONE_VERIFICATION` service. If both email and phone verification are enabled, the account becomes active only after both channels are verified.

To provision an application client for the implemented authentication APIs, enable Signup/Login through the platform configuration API, then create a separate confidential client with the needed scopes:

```powershell
docker compose exec api python -m alzando_authorization.cli create-client --application-id YOUR_APPLICATION_ID --scope authentication:signup --scope authentication:login
```

Add `--scope authentication:recovery` when the application's client also needs password recovery.

Save the generated secret securely. Do not paste it into source control or chat. Each scope is rejected at token issuance if its service is disabled for that application.

## Production deployment requirements

- Set `TOKEN_ISSUER`, `TOKEN_AUDIENCE`, and `JWT_PRIVATE_KEY_FILE` to production values. Mount the signing key from a secret manager; never commit it to Git. `JWT_PUBLIC_KEY_FILE` can supply the verification key separately.
- Use managed PostgreSQL, secret storage, TLS, and operational monitoring.
- Public-client authentication, email/phone verification, OTP, MFA, passkeys, social login, application-user tokens, and audit-event APIs remain planned feature slices.
- The accepted application-type values and detailed per-service configuration schemas are initial V1 choices and should be reviewed against product requirements.

## API response envelope

Successes and service errors use the working response shape from the Alzando specification: `success`, `status`, `data`, `error`, and `request_id`. The exact public contract and HTTP mappings remain subject to the specification's open design decisions.
