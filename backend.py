'''
Name: backend.py
Authors: Jack Morice, Nick Grieco, Alex Carrillo, Gunther Luechtefield
Description: This file contains the backend implmenetation of enclav3. It defines the construction of the database, encryption and decryption of entires,
as well as the CRUD operations on the database. The backend is used by the Flask application defined in app.py to handle all interactions with the database and encryption logic.
Inputs: User interactions with the web interface (add entry, list entries, get entry, delete entry, update entry)
Outputs: Encrypted entries stored in the SQLite database, decrypted entries returned to the web application for display, and error messages for invalid operations (e.g., incorrect master password, entry not found)
Resources: ChatGPT was used in the implementation of the encryption and database logic.
'''
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


def _get_default_db_path() -> str: #Helper function to get the default path for the database
	base_dir = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or os.path.dirname(__file__)
	app_dir = os.path.join(base_dir, "Enclav3")
	os.makedirs(app_dir, exist_ok=True)
	return os.path.join(app_dir, "data.db")


DEFAULT_DB = _get_default_db_path() #Default path to SQL database
PBKDF2_ITERATIONS = 200_000 #Default iterations (low)
TIERS = ("low", "medium", "high") #Tier names
DEFAULT_TIER = "low" #Default security tier is set to "low"
TIER_ITERATIONS = {
	"low": PBKDF2_ITERATIONS,
	"medium": 300_000,
	"high": 500_000,
}

@dataclass
class Entry: #Data class representing a password entry
	site: str #Website URL
	username: str #Username
	password: str #Password in plaintext (will be encrypted before storage)
	notes: Optional[str] = None #Optional notes about the entry
	tier: str = DEFAULT_TIER #Security tier for the entry, which determines the number of iterations used in key derivation (default is "low")

def _utc_now() -> str: #Helper function to get the current time in the computer's local timezone in 12 hour HR:MM AM/PM format
	return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %I:%M %p")

def _derive_key(master_password: str, salt: bytes, iterations: int) -> bytes: #Derive a key from the master password using PBKDF2 with HMAC-SHA256
	#Use PBKDF2 with HMAC-SHA256 to derive a key from the master password, salt, and iteration count. 
	#The derived key is then encoded in URL-safe base64 to be used with Fernet for encryption and decryption of password entries.
	key = pbkdf2_hmac(
		"sha256",
		master_password.encode("utf-8"),
		salt,
		iterations,
		dklen=32,
	)
	return base64.urlsafe_b64encode(key)

def _tier_salt_key(tier: str) -> str: #Helper function to get the metadata key for the salt of a given tier
	return f"tier_{tier}_salt"

def _tier_iterations_key(tier: str) -> str: #Helper function to get the metadata key for the iteration count of a given tier
	return f"tier_{tier}_iterations"

def _get_connection(db_path: str) -> sqlite3.Connection: #Helper function to connect to the db
	conn = sqlite3.connect(db_path)
	conn.execute("PRAGMA foreign_keys = ON")
	return conn

def _load_meta(db_path: str) -> dict[str, str]: #Load metadata from database
	if not os.path.exists(db_path):
		raise RuntimeError("Database not found. Run 'init' first.")

	with _get_connection(db_path) as conn:
		rows = conn.execute("SELECT key, value FROM meta").fetchall()
		meta = {key: value for key, value in rows}

	return meta

def init_db(db_path: str, master_password: str) -> None: #Initialize the database with the master password and security tier
	if os.path.exists(db_path): #If the database already exists, raise an error to prevent overwriting existing data
		raise RuntimeError("Database already exists.")

	salt = os.urandom(16) #Generate a random salt for key derivation
	key = _derive_key(master_password, salt, PBKDF2_ITERATIONS) #Derive the encryption key from the master password, salt, and iteration count
	verifier = hmac.new(key, b"verify", "sha256").digest() #Create a verifier using HMAC to allow future verification of the master password without storing it directly

	with _get_connection(db_path) as conn: #Create the database schema and store the metadata (salt, iterations, verifier) in the meta table
		conn.executescript( #Script to create tables for metadata and password entries.
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
				created_at TEXT NOT NULL,
				tier TEXT NOT NULL DEFAULT 'low'
			);
			"""
		)

		conn.execute( #Store the salt, iteration count, and verifier in the meta table for later use in verifying the master password and deriving the key
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("salt", base64.b64encode(salt).decode("utf-8")),
		)
		conn.execute( #Store the iteration count in the meta table
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("iterations", str(PBKDF2_ITERATIONS)),
		)
		conn.execute( #Store the verifier in the meta table
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("verifier", base64.b64encode(verifier).decode("utf-8")),
		)

		low_salt_key = _tier_salt_key(DEFAULT_TIER) #Store the salt and iteration count for the default tier
		low_iter_key = _tier_iterations_key(DEFAULT_TIER) #Store the salt and iteration count for the default tier
		conn.execute( #Store the salt and iteration count for the default tier in the meta table, using the helper functions to generate the appropriate keys for the tier
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			(low_salt_key, base64.b64encode(salt).decode("utf-8")),
		)
		conn.execute( #Store the salt and iteration count for the default tier
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			(low_iter_key, str(PBKDF2_ITERATIONS)),
		)

		for tier_name in TIERS: #For each additional tier (beyond the default), generate unique salt and itr count value to be stored in the meta table
			if tier_name == DEFAULT_TIER:
				continue
			tier_salt = os.urandom(16)
			conn.execute(
				"INSERT INTO meta (key, value) VALUES (?, ?)",
				(_tier_salt_key(tier_name), base64.b64encode(tier_salt).decode("utf-8")),
			)
			conn.execute(
				"INSERT INTO meta (key, value) VALUES (?, ?)",
				(_tier_iterations_key(tier_name), str(TIER_ITERATIONS[tier_name])),
			)

def _verify_master_password(meta: dict[str, str], master_password: str) -> bytes:
	try: #Extract the salt, iteration count, and verifier from the metadata, decoding them from base64 as needed
		salt = base64.b64decode(meta["salt"])
		iterations = int(meta["iterations"])
		verifier = base64.b64decode(meta["verifier"])
	except KeyError as exc: #If any of the required metadata keys are missing, raise an error indicating that the database is corrupted or not properly initialized
		raise RuntimeError("Database metadata is missing or corrupted.") from exc

	key = _derive_key(master_password, salt, iterations) #Derive the key from the provided master password and the stored salt and iteration count
	expected = hmac.new(key, b"verify", "sha256").digest() #Compute the expected verifier using HMAC with the derived key
	if not hmac.compare_digest(expected, verifier): #Compare the computed verifier with the stored verifier in a way that is resistant to timing attacks. If they do not match, raise an error indicating that the master password is incorrect.
		raise RuntimeError("Invalid master password.") #Raise an error if the master password is incorrect

	return key

def _load_master_key(db_path: str, master_password: str) -> bytes: 
	#Helper function to load the master key by verifying the master password against the stored verifier in the database
	meta = _load_meta(db_path)
	return _verify_master_password(meta, master_password)

def verify_master_password(db_path: str, master_password: str) -> None: #Helper function to verify the master password by attempting to load the master key. If the master password is incorrect, this will raise an error from the _load_master_key function.
	_load_master_key(db_path, master_password)

def add_entry(db_path: str, entry: Entry) -> None: #Add a new password entry to the database, encrypting the password using the master key derived from the master password
	with _get_connection(db_path) as conn:
		conn.execute( #Add the new entry to the entries table, storing the site, username, encrypted password, notes, and creation timestamp
			"""
			INSERT INTO entries (site, username, password_enc, notes, created_at, tier)
			VALUES (?, ?, ?, ?, ?, ?)
			""",
			(entry.site, entry.username, entry.password, entry.notes, _utc_now(), entry.tier),
		)

def list_entries(db_path: str) -> list[dict[str, str]]: #List all entries in the database
	with _get_connection(db_path) as conn:
		rows = conn.execute(
			"SELECT id, site, username, password_enc, notes, created_at, tier FROM entries ORDER BY site"
		).fetchall()
	entries: list[dict[str, str]] = []
	for row in rows:
		entry_id, site, username, password_enc, notes, created_at, tier = row
		entries.append(
			{
				"id": str(entry_id),
				"site": site,
				"username": username,
				"password": password_enc,
				"notes": notes or "",
				"created_at": created_at,
				"tier": tier,
			}
		)
	return entries #Return all entries

def delete_entry(db_path: str, master_password: str, entry_id: int) -> None: #Delete entries in the database
	_load_master_key(db_path, master_password)
	with _get_connection(db_path) as conn:
		cur = conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
		if cur.rowcount == 0:
			print("Entry not found.")
		else:
			print("Entry deleted.")

def _prompt_master_password(confirm: bool = False) -> str: 
	#Helper function to prompt the user for the master password
	while True:
		pwd = getpass.getpass("Master password: ")
		if not confirm:
			return pwd
		confirm_pwd = getpass.getpass("Confirm master password: ")
		if pwd != confirm_pwd:
			print("Passwords do not match. Try again.")
			continue
		return pwd


def build_parser() -> argparse.ArgumentParser: #Parser for the command line portion of the app, these all run each function
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
	sub_add.add_argument("--tier", choices=list(TIERS), default=DEFAULT_TIER)

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
	sub_update.add_argument("--tier", choices=list(TIERS))

	return parser


def main() -> None:
	parser = build_parser() #Build the command-line argument parser and parse the arguments provided by the user when running the script. This will determine which command the user wants to execute (e.g., init, add, list, get, delete, update) and will provide the necessary parameters for that command.
	args = parser.parse_args() #Parse the command-line arguments provided by the user when running the script, which will determine which command to execute and with what parameters (e.g., database path, site, username, password, notes, etc.) based on the defined argument parser.

	if getattr(args, "db", None): #Determine the database path to use based on the command-line arguments.
		db_path = args.db

	if args.command == "init": #Initializing
		master_password = _prompt_master_password(confirm=True)
		init_db(db_path, master_password)
		print(f"Initialized database at {db_path}")
		return

	master_password = _prompt_master_password()

	if args.command == "add": #add entry
		password = args.password or getpass.getpass("Password: ")
		entry = Entry(site=args.site, username=args.username, password=password, notes=args.notes, tier=args.tier)
		add_entry(db_path, entry)
		print("Entry added.")
		return

	if args.command == "list": #list all entries
		list_entries(db_path)
		return

	if args.command == "delete": #Delete an entry by ID
		delete_entry(db_path, master_password, args.id)
		return

if __name__ == "__main__":
	main()
