import argparse
import json

from alzando_authorization.clients import create_confidential_client
from alzando_authorization.database import SessionLocal

ALLOWED_SCOPES = {
    "authorization:manage", "authorization:check",
    "authentication:signup", "authentication:login", "authentication:recovery",
    "authentication:verify",
    "authentication:verify_phone",
}


def main() -> None:
    parser = argparse.ArgumentParser(prog="alzando-authz")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser(
        "create-client", help="Provision a confidential client outside the public API"
    )
    create.add_argument("--application-id", required=True)
    create.add_argument("--scope", action="append", choices=sorted(ALLOWED_SCOPES), required=True)
    commands.add_parser(
        "create-platform-admin", help="Provision an operator client for application management"
    )
    args = parser.parse_args()

    if args.command == "create-platform-admin":
        application_id = "alzando_platform"
        scopes = ["platform:manage"]
    else:
        application_id = args.application_id
        scopes = args.scope

    with SessionLocal() as db:
        client_id, client_secret = create_confidential_client(db, application_id, scopes)
    print(json.dumps({
        "client_id": client_id,
        "client_secret": client_secret,
        "application_id": application_id,
        "scopes": sorted(set(scopes)),
        "notice": "Copy the secret now. Only its hash is stored, so it cannot be retrieved later.",
    }, indent=2))


if __name__ == "__main__":
    main()
