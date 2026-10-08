"""Single source of truth for API scopes and the service each scope depends on."""

# Scope -> service that must be enabled for the application to use the scope.
SCOPE_TO_SERVICE: dict[str, str] = {
    "authorization:manage": "AUTHORIZATION",
    "authorization:check": "AUTHORIZATION",
    "authentication:signup": "SIGNUP",
    "authentication:login": "LOGIN",
    "authentication:recovery": "PASSWORD_RECOVERY",
    "authentication:verify": "EMAIL_VERIFICATION",
    "authentication:verify_phone": "PHONE_VERIFICATION",
    "authentication:otp": "OTP",
    "authentication:mfa": "MFA",
    "authentication:token": "TOKEN",
    "audit:read": "AUDIT",
}

# Scopes that are never granted automatically; an operator must provision them explicitly.
EXPLICIT_ONLY_SCOPES = frozenset({"authorization:manage"})


def default_scopes_for_services(service_codes: set[str] | frozenset[str]) -> list[str]:
    """Return the scopes a client receives automatically for the given enabled services."""
    return sorted(
        scope
        for scope, service in SCOPE_TO_SERVICE.items()
        if service in service_codes and scope not in EXPLICIT_ONLY_SCOPES
    )
