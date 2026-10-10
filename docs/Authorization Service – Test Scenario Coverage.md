# Authorization Service – Test Scenario Coverage

**Status legend**
- ✅ Implemented — identified in previously discussed tests
- 🟡 Partially implemented — part of the scenario is covered; detailed assertions need verification
- ⬜ Not verified — requires inspection of existing tests
- ❌ Not implemented — confirmed missing after test-suite inspection

## 1. Application Management

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| APP-01 | Register application with valid data | Application created successfully | ⬜ Not verified | P1 |
| APP-02 | Register duplicate application ID | Duplicate registration rejected | ⬜ Not verified | P1 |
| APP-03 | Register application with missing fields | Validation error returned | ⬜ Not verified | P1 |
| APP-04 | Register application with malformed data | Request rejected | ⬜ Not verified | P2 |
| APP-05 | Access using inactive application | Access denied | ✅ Implemented | P1 |
| APP-06 | Access disabled application service | Access denied | ⬜ Not verified | P1 |
| APP-07 | Access resources belonging to another application | Access denied | ⬜ Not verified | P1 |

## 2. User Registration and Account Management

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| USR-01 | Register user with valid details | Account created successfully | 🟡 Partially implemented | P1 |
| USR-02 | Register duplicate email | Duplicate registration rejected | ⬜ Not verified | P1 |
| USR-03 | Register with invalid email | Validation error returned | ⬜ Not verified | P1 |
| USR-04 | Register with missing required fields | Validation error returned | ⬜ Not verified | P1 |
| USR-05 | Register with weak password | Password policy enforced | ⬜ Not verified | P1 |
| USR-06 | Login using inactive account | Authentication rejected | ⬜ Not verified | P1 |
| USR-07 | Login using locked or disabled account | Authentication rejected | ⬜ Not verified | P1 |
| USR-08 | Deactivate account with active sessions | Sessions invalidated according to policy | ⬜ Not verified | P1 |
| USR-09 | Access another user's resources | Access denied | ⬜ Not verified | P1 |

## 3. Authentication and Login

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| AUTH-01 | Login with valid credentials | Tokens issued successfully | ✅ Implemented | P1 |
| AUTH-02 | Login with incorrect password | Authentication rejected | ⬜ Not verified | P1 |
| AUTH-03 | Login with unknown account | Authentication rejected without account enumeration | ⬜ Not verified | P1 |
| AUTH-04 | Login with missing credentials | Validation error returned | ⬜ Not verified | P1 |
| AUTH-05 | Login with malformed request body | Validation error returned | ⬜ Not verified | P1 |
| AUTH-06 | Login with empty credentials | Request rejected | ⬜ Not verified | P1 |
| AUTH-07 | Repeated failed login attempts | Rate limit or lockout policy enforced | ⬜ Not verified | P1 |
| AUTH-08 | Login after account deactivation | Authentication rejected | ⬜ Not verified | P1 |
| AUTH-09 | Login after application deactivation | Authentication rejected | ⬜ Not verified | P1 |
| AUTH-10 | Verify token response contract | Required fields returned; sensitive data excluded | ⬜ Not verified | P1 |

## 4. Access Token Validation

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| TOK-01 | Access protected endpoint with valid token | Request succeeds | 🟡 Partially implemented | P1 |
| TOK-02 | Use expired access token | Authentication rejected | ⬜ Not verified | P1 |
| TOK-03 | Use malformed access token | Authentication rejected | ⬜ Not verified | P1 |
| TOK-04 | Use token with invalid signature | Authentication rejected | ⬜ Not verified | P1 |
| TOK-05 | Use token with invalid issuer or audience | Token rejected when these claims are validated | ⬜ Not verified | P1 |
| TOK-06 | Access endpoint without token | Authentication rejected | ⬜ Not verified | P1 |
| TOK-07 | Use incorrect Authorization header format | Authentication rejected | ⬜ Not verified | P1 |
| TOK-08 | Use token after session deletion | Authentication rejected | ✅ Implemented | P1 |
| TOK-09 | Use token associated with inactive account | Authentication rejected | ✅ Implemented | P1 |
| TOK-10 | Use token associated with inactive application | Authentication rejected | ✅ Implemented | P1 |
| TOK-11 | Use revoked access token | Authentication rejected | 🟡 Partially implemented | P1 |
| TOK-12 | Ordinary user accesses admin endpoint | Authorization denied | ⬜ Not verified | P1 |
| TOK-13 | Access another user's protected resource | Access denied | ⬜ Not verified | P1 |
| TOK-14 | Tamper with token claims | Token rejected | ⬜ Not verified | P1 |
| TOK-15 | Test token expiration boundary | Expiration handled consistently | ⬜ Not verified | P2 |

## 5. Refresh Token Lifecycle

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| REF-01 | Refresh using valid refresh token | New access token issued | ✅ Implemented | P1 |
| REF-02 | Refresh using revoked refresh token | Request rejected | ✅ Implemented | P1 |
| REF-03 | Refresh using expired token | Request rejected | ⬜ Not verified | P1 |
| REF-04 | Refresh using malformed token | Request rejected | ⬜ Not verified | P1 |
| REF-05 | Reuse old refresh token after rotation | Reuse rejected according to policy | ⬜ Not verified | P1 |
| REF-06 | Refresh token associated with deleted session | Request rejected | ⬜ Not verified | P1 |
| REF-07 | Refresh token associated with inactive account | Request rejected | ⬜ Not verified | P1 |
| REF-08 | Refresh token associated with inactive application | Request rejected | ⬜ Not verified | P1 |
| REF-09 | Concurrent refresh requests using the same token | No unintended duplicate valid token chains | ⬜ Not verified | P1 |
| REF-10 | Refresh request without token | Authentication rejected | ⬜ Not verified | P1 |
| REF-11 | Use refresh token as access token | Request rejected | ⬜ Not verified | P1 |
| REF-12 | Refresh after logout | Request rejected | ✅ Implemented | P1 |

## 6. Logout, Revocation and Session Management

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| SES-01 | Signup → login → issue tokens → refresh → revoke | Lifecycle completes successfully | 🟡 Partially implemented | P1 |
| SES-02 | Use access token after revocation | Authentication rejected | ✅ Implemented | P1 |
| SES-03 | Use refresh token after logout/revocation | Authentication rejected | ✅ Implemented | P1 |
| SES-04 | Logout without token | Documented error or idempotent behavior | ⬜ Not verified | P1 |
| SES-05 | Logout with invalid token | Request handled according to contract | ⬜ Not verified | P1 |
| SES-06 | Logout more than once | Idempotent or documented response | ⬜ Not verified | P2 |
| SES-07 | Revoke one session while another exists | Only intended session revoked | ⬜ Not verified | P1 |
| SES-08 | Delete session from database | Associated access token rejected | ✅ Implemented | P1 |
| SES-09 | Use expired session | Session cannot authorize requests | ⬜ Not verified | P1 |
| SES-10 | Revocation operation fails | No inconsistent token/session state | ⬜ Not verified | P1 |

## 7. API Validation and HTTP Error Handling

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| API-01 | Submit request with missing required fields | Documented validation response | ⬜ Not verified | P1 |
| API-02 | Submit incorrect field types | Validation error returned | ⬜ Not verified | P1 |
| API-03 | Call unknown endpoint | HTTP 404 | ⬜ Not verified | P2 |
| API-04 | Use unsupported HTTP method | HTTP 405 where applicable | ⬜ Not verified | P2 |
| API-05 | Submit malformed JSON | Request rejected safely | ⬜ Not verified | P1 |
| API-06 | Trigger unexpected internal exception | Safe 5xx response; no sensitive details leaked | ⬜ Not verified | P1 |
| API-07 | Validate error response schema | Consistent documented error format | ⬜ Not verified | P2 |
| API-08 | Create resource successfully | Correct status, response and persisted state | ⬜ Not verified | P1 |
| API-09 | Update resource successfully | Updated state returned or persisted | ⬜ Not verified | P1 |
| API-10 | Database transaction fails | No partial or inconsistent state | ⬜ Not verified | P1 |

## 8. Security and Rate Limiting

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| SEC-01 | Validate production configuration | Invalid production configuration rejected | ✅ Implemented | P1 |
| SEC-02 | Missing JWT private key configuration | Configuration validation fails | ✅ Implemented | P1 |
| SEC-03 | Missing or short challenge HMAC secret | Configuration validation fails | ✅ Implemented | P1 |
| SEC-04 | Use development identity header when prohibited | Request rejected | ⬜ Not verified | P1 |
| SEC-05 | Exceed configured rate limit | HTTP 429 or documented response | ⬜ Not verified | P1 |
| SEC-06 | Verify rate-limit isolation | Limits follow intended client/user policy | ⬜ Not verified | P1 |
| SEC-07 | Verify password storage | Passwords are not stored in plaintext | ⬜ Not verified | P1 |
| SEC-08 | Check logs and error responses for secrets | No sensitive data leaked | ⬜ Not verified | P1 |
| SEC-09 | Validate CORS configuration | Only permitted origins and methods allowed | ⬜ Not verified | P2 |
| SEC-10 | Spoof proxy headers | Cannot bypass configured trust/security rules | ⬜ Not verified | P1 |
| SEC-11 | Use unsupported JWT signing algorithm | Token rejected | ⬜ Not verified | P1 |
| SEC-12 | Validate HMAC challenge | Tampered or invalid challenge rejected | ⬜ Not verified | P1 |
| SEC-13 | Check source-controlled configuration | Production secrets are not committed | ⬜ Not verified | P1 |
| SEC-14 | Configure unsafe production defaults | Startup/configuration validation fails | ✅ Implemented | P1 |

## 9. Reliability, Integration and Test Framework

| ID | Test Scenario | Expected Result | Status | Priority |
|---|---|---|---|---|
| REL-01 | Execute tests sequentially | No cross-test state leakage | ⬜ Not verified | P1 |
| REL-02 | Execute tests in different orders | Results remain consistent | ⬜ Not verified | P2 |
| REL-03 | Run tests in parallel | No shared-state collisions | ⬜ Not verified | P2 |
| REL-04 | Simulate database failure | Safe error and clean recovery | ⬜ Not verified | P2 |
| REL-05 | Simulate email/SMS provider failure, if integrated | Defined failure behavior | ⬜ Not verified | P2 |
| REL-06 | Enable/disable application services | Access reflects current configuration | ⬜ Not verified | P1 |
| REL-07 | Validate health/readiness endpoints | Correct status and dependency behavior | ⬜ Not verified | P2 |
| REL-08 | Validate fixture teardown and dependency cleanup | Overrides, database and caches cleaned up | ⬜ Not verified | P1 |
| REL-09 | Execute full test suite | Tests pass consistently | 🟡 Previously reported: 87 passed, 1 skipped | P1 |
| REL-10 | Measure line and branch coverage | Critical security paths covered | ⬜ Not verified | P2 |

## 10. Priority Definitions

| Priority | Meaning |
|---|---|
| P1 | Critical authentication, authorization, token lifecycle, security or correctness scenario |
| P2 | Important edge case, reliability, configuration or maintainability scenario |
| P3 | Optional enhancement or lower-risk scenario |

## 11. Coverage Update Rules

1. Inspect existing test functions before adding new tests.
2. Mark a scenario **Implemented** only when the corresponding test and its assertions are verified.
3. Mark a scenario **Partially implemented** when only part of the expected behavior is covered.
4. Mark a scenario **Not implemented** only after confirming the test is missing.
5. Update this table whenever new test cases are added or existing tests are enhanced.
6. Validate both HTTP responses and relevant business/security state, not just status codes.

**Current baseline:** The previously reported full-suite result was `87 passed, 1 skipped`. This is a historical result, not a fresh test run. The complete coverage status must be finalized after inspecting the current repository.