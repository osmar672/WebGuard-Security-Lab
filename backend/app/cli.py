"""Administrative commands; user creation is intentionally CLI-only by default."""
import argparse
import getpass
import re
import sys

from sqlalchemy import select

from app.auth import hash_password
from app.config import get_settings
from app.db import Database
from app.models import User, UserRole


def create_user(role: str) -> int:
    email = input("Correo de usuario: ").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        print("Error: correo no válido.", file=sys.stderr)
        return 2
    password = getpass.getpass("Contraseña (mínimo 14 caracteres): ")
    confirmation = getpass.getpass("Confirmar contraseña: ")
    if not 14 <= len(password) <= 1024:
        print("Error: la contraseña debe tener entre 14 y 1024 caracteres.", file=sys.stderr)
        return 2
    if password != confirmation:
        print("Error: las contraseñas no coinciden.", file=sys.stderr)
        return 2

    db = Database(get_settings().database_url)
    with db.SessionLocal() as session:
        if session.scalar(select(User.id).where(User.email == email)):
            print("Error: ese correo ya está registrado.", file=sys.stderr)
            return 2
        user = User(email=email, password_hash=hash_password(password), role=role, is_active=True)
        session.add(user)
        session.commit()
    print(f"Usuario {email} creado con rol {role}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user", help="Create a local WebGuard user")
    create.add_argument("--role", choices=[r.value for r in UserRole], default="viewer")
    args = parser.parse_args()
    if args.command == "create-user":
        return create_user(args.role)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
