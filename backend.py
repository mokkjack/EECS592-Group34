import argparse
import base64
import getpass
import hmac
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import pbkdf2_hmac
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_DB = os.path.join(os.path.dirname(__file__), "passwords.db")
PBKDF2_ITERATIONS = 200_000


@dataclass
class Entry:
	site: str
	username: str
	password: str
	notes: Optional[str] = None


def _utc_now() -> str:
	return datetime.now(timezone.utc).isoformat()


def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
	key = pbkdf2_hmac(
		"sha256",
		master_password.encode("utf-8"),
		salt,
		iterations,
		dklen=32,
	)
	return base64.urlsafe_b64encode(key)


def _get_connection(db_path: str) -> sqlite3.Connection:
	conn = sqlite3.connect(db_path)
	conn.execute("PRAGMA foreign_keys = ON")
	return conn


def init_db(db_path: str, master_password: str) -> None:
	if os.path.exists(db_path):
		raise RuntimeError("Database already exists.")

	salt = os.urandom(16)
	key = _derive_key(master_password, salt, PBKDF2_ITERATIONS)
	verifier = hmac.new(key, b"verify", "sha256").digest()

	with _get_connection(db_path) as conn:
		conn.executescript(
			"""
			CREATE TABLE meta (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);

			CREATE TABLE entries (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				site TEXT NOT NULL,
				username TEXT NOT NULL,
				password_enc TEXT NOT NULL,
				notes TEXT,
				created_at TEXT NOT NULL
			);
			"""
		)

		conn.execute(
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("salt", base64.b64encode(salt).decode("utf-8")),
		)
		conn.execute(
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("iterations", str(PBKDF2_ITERATIONS)),
		)
		conn.execute(
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("verifier", base64.b64encode(verifier).decode("utf-8")),
		)


def _load_master_key(db_path: str, master_password: str) -> bytes:
	if not os.path.exists(db_path):
		raise RuntimeError("Database not found. Run 'init' first.")

	with _get_connection(db_path) as conn:
		rows = conn.execute("SELECT key, value FROM meta").fetchall()
		meta = {key: value for key, value in rows}

	try:
		salt = base64.b64decode(meta["salt"])
		iterations = int(meta["iterations"])
		verifier = base64.b64decode(meta["verifier"])
	except KeyError as exc:
		raise RuntimeError("Database metadata is missing or corrupted.") from exc

	key = _derive_key(master_password, salt, iterations)
	expected = hmac.new(key, b"verify", "sha256").digest()
	if not hmac.compare_digest(expected, verifier):
		raise RuntimeError("Invalid master password.")

	return key


def verify_master_password(db_path: str, master_password: str) -> None:
	_load_master_key(db_path, master_password)


def add_entry(db_path: str, master_password: str, entry: Entry) -> None:
	key = _load_master_key(db_path, master_password)
	fernet = Fernet(key)
	encrypted = fernet.encrypt(entry.password.encode("utf-8")).decode("utf-8")

	with _get_connection(db_path) as conn:
		conn.execute(
			"""
			INSERT INTO entries (site, username, password_enc, notes, created_at)
			VALUES (?, ?, ?, ?, ?)
			""",
			(entry.site, entry.username, encrypted, entry.notes, _utc_now()),
		)


def list_entries(db_path: str, master_password: str) -> None:
	_load_master_key(db_path, master_password)
	with _get_connection(db_path) as conn:
		rows = conn.execute(
			"SELECT id, site, username, created_at FROM entries ORDER BY site"
		).fetchall()

	if not rows:
		print("No entries found.")
		return

	for row in rows:
		entry_id, site, username, created_at = row
		print(f"{entry_id}: {site} | {username} | {created_at}")


def list_entries_decrypted(db_path: str, master_password: str) -> list[dict[str, str]]:
	key = _load_master_key(db_path, master_password)
	fernet = Fernet(key)
	with _get_connection(db_path) as conn:
		rows = conn.execute(
			"SELECT id, site, username, password_enc, notes, created_at FROM entries ORDER BY site"
		).fetchall()

	entries: list[dict[str, str]] = []
	for row in rows:
		entry_id, site, username, password_enc, notes, created_at = row
		password = fernet.decrypt(password_enc.encode("utf-8")).decode("utf-8")
		entries.append(
			{
				"id": str(entry_id),
				"site": site,
				"username": username,
				"password": password,
				"notes": notes or "",
				"created_at": created_at,
			}
		)

	return entries


def get_entry(db_path: str, master_password: str, *, entry_id: int | None, site: str | None) -> None:
	key = _load_master_key(db_path, master_password)
	fernet = Fernet(key)

	with _get_connection(db_path) as conn:
		if entry_id is not None:
			row = conn.execute(
				"SELECT site, username, password_enc, notes, created_at FROM entries WHERE id = ?",
				(entry_id,),
			).fetchone()
		else:
			row = conn.execute(
				"SELECT site, username, password_enc, notes, created_at FROM entries WHERE site = ?",
				(site,),
			).fetchone()

	if not row:
		print("Entry not found.")
		return

	site_val, username, password_enc, notes, created_at = row
	try:
		password = fernet.decrypt(password_enc.encode("utf-8")).decode("utf-8")
	except InvalidToken:
		raise RuntimeError("Failed to decrypt entry. Master password may be incorrect.")

	print(f"Site: {site_val}")
	print(f"Username: {username}")
	print(f"Password: {password}")
	if notes:
		print(f"Notes: {notes}")
	print(f"Created: {created_at}")


def delete_entry(db_path: str, master_password: str, entry_id: int) -> None:
	_load_master_key(db_path, master_password)
	with _get_connection(db_path) as conn:
		cur = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
		if cur.rowcount == 0:
			print("Entry not found.")
		else:
			print("Entry deleted.")


def update_entry(
	db_path: str,
	master_password: str,
	entry_id: int,
	site: Optional[str],
	username: Optional[str],
	password: Optional[str],
	notes: Optional[str],
) -> None:
	key = _load_master_key(db_path, master_password)
	fernet = Fernet(key)

	fields = []
	params = []
	if site:
		fields.append("site = ?")
		params.append(site)
	if username:
		fields.append("username = ?")
		params.append(username)
	if password:
		encrypted = fernet.encrypt(password.encode("utf-8")).decode("utf-8")
		fields.append("password_enc = ?")
		params.append(encrypted)
	if notes is not None:
		fields.append("notes = ?")
		params.append(notes)

	if not fields:
		print("Nothing to update.")
		return

	params.append(entry_id)
	with _get_connection(db_path) as conn:
		cur = conn.execute(
			f"UPDATE entries SET {', '.join(fields)} WHERE id = ?",
			params,
		)
		if cur.rowcount == 0:
			print("Entry not found.")
		else:
			print("Entry updated.")


def _prompt_master_password(confirm: bool = False) -> str:
	while True:
		pwd = getpass.getpass("Master password: ")
		if not confirm:
			return pwd
		confirm_pwd = getpass.getpass("Confirm master password: ")
		if pwd != confirm_pwd:
			print("Passwords do not match. Try again.")
			continue
		return pwd


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Simple local password manager")
	parser.add_argument("--db", default=DEFAULT_DB, help="Path to the SQLite database")

	sub = parser.add_subparsers(dest="command", required=True)

	sub_init = sub.add_parser("init", help="Initialize the password database")
	sub_init.add_argument("--db", default=DEFAULT_DB)

	sub_add = sub.add_parser("add", help="Add a new entry")
	sub_add.add_argument("--db", default=DEFAULT_DB)
	sub_add.add_argument("--site", required=True)
	sub_add.add_argument("--username", required=True)
	sub_add.add_argument("--password")
	sub_add.add_argument("--notes")

	sub_list = sub.add_parser("list", help="List entries")
	sub_list.add_argument("--db", default=DEFAULT_DB)

	sub_get = sub.add_parser("get", help="Get an entry")
	sub_get.add_argument("--db", default=DEFAULT_DB)
	group = sub_get.add_mutually_exclusive_group(required=True)
	group.add_argument("--id", type=int)
	group.add_argument("--site")

	sub_delete = sub.add_parser("delete", help="Delete an entry")
	sub_delete.add_argument("--db", default=DEFAULT_DB)
	sub_delete.add_argument("--id", type=int, required=True)

	sub_update = sub.add_parser("update", help="Update an entry")
	sub_update.add_argument("--db", default=DEFAULT_DB)
	sub_update.add_argument("--id", type=int, required=True)
	sub_update.add_argument("--site")
	sub_update.add_argument("--username")
	sub_update.add_argument("--password")
	sub_update.add_argument("--notes")

	return parser


def main() -> None:
	parser = build_parser()
	args = parser.parse_args()

	if args.command == "init":
		master_password = _prompt_master_password(confirm=True)
		init_db(args.db, master_password)
		print(f"Initialized database at {args.db}")
		return

	master_password = _prompt_master_password()

	if args.command == "add":
		password = args.password or getpass.getpass("Password: ")
		entry = Entry(site=args.site, username=args.username, password=password, notes=args.notes)
		add_entry(args.db, master_password, entry)
		print("Entry added.")
		return

	if args.command == "list":
		list_entries(args.db, master_password)
		return

	if args.command == "get":
		get_entry(args.db, master_password, entry_id=args.id, site=args.site)
		return

	if args.command == "delete":
		delete_entry(args.db, master_password, args.id)
		return

	if args.command == "update":
		update_entry(
			args.db,
			master_password,
			args.id,
			args.site,
			args.username,
			args.password,
			args.notes,
		)
		return


if __name__ == "__main__":
	main()
