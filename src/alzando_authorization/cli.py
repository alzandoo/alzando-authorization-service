import argparse
import json

from alzando_authorization.clients import create_confidential_client
from alzando_authorization.database import SessionLocal

ALLOWED_SCOPES = {"authorization:manage", "authorization:check"}


def main() -> None:
    parser = argparse.ArgumentParser(prog="alzando-authz")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser(
        "create-client", help="Provision a confidential client outside the public API"
    )
    create.add_argument("--application-id", required=True)
    create.add_argument("--scope", action="append", choices=sorted(ALLOWED_SCOPES), required=True)
    args = parser.parse_args()

    with SessionLocal() as db:
        client_id, client_secret = create_confidential_client(db, args.application_id, args.scope)
    print(json.dumps({
        "client_id": client_id,
        "client_secret": client_secret,
        "application_id": args.application_id,
        "scopes": sorted(set(args.scope)),
        "notice": "Copy the secret now. Only its hash is stored, so it cannot be retrieved later.",
    }, indent=2))


if __name__ == "__main__":
    main()
