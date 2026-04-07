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

import pyotp
import qrcode
from io import BytesIO
from cryptography.fernet import Fernet, InvalidToken
import csv
import io


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


#hashes the pin 
def _hash_pin(pin: str, salt: bytes) -> bytes:
	return pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, 100_000)

# verifies a PIN entered by the user against the stored hash in the database. This will be for tier 2/3 access. 
def verify_pin(db_path: str, pin: str) -> bool:
	meta = _load_meta(db_path)
	if meta.get("pin_enabled") != "True":
		return True  # PIN not setup skip check

	pin_salt = base64.b64decode(meta["pin_salt"])
	stored_hash = base64.b64decode(meta["pin_hash"])
	computed = _hash_pin(pin, pin_salt)
	return hmac.compare_digest(computed, stored_hash) #compare the computed hash with stored hash of pin.

#hash the answer for security questions 
def _hash_answer(answer: str, salt: bytes) -> bytes:
	normalized = answer.strip().lower() 
	return pbkdf2_hmac("sha256", normalized.encode("utf-8"), salt, 100_000)

# verifies a challenge answer entered by the user against the stored hash. This will be for tier 2/3 access.
def verify_challenge_answer(db_path: str, answer: str) -> bool:
	meta = _load_meta(db_path)
	if meta.get("challenge_enabled") != "True": # Challenge question not setup skip check
		return True 

	answer_salt = base64.b64decode(meta["challenge_answer_salt"])
	stored_hash = base64.b64decode(meta["challenge_answer_hash"])
	computed = _hash_answer(answer, answer_salt)
	return hmac.compare_digest(computed, stored_hash) 

def init_db(db_path: str, master_password: str, pin: Optional[str] = None, 
            challenge_question: Optional[str] = None, challenge_answer: Optional[str] = None) -> None: #Initialize the database with the master password and security tier
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

			CREATE TABLE vault_files (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				filename TEXT NOT NULL,
				mime_type TEXT NOT NULL,
				file_data_enc TEXT NOT NULL,
				notes TEXT,
				created_at TEXT NOT NULL
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
		conn.execute( #Store the 2FA enabled flag (default: False)
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("2fa_enabled", "False"),
		)
		conn.execute( #Store the 2FA secret (empty by default)
			"INSERT INTO meta (key, value) VALUES (?, ?)",
			("2fa_secret", ""),
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
		# PIN code 
		pin_salt = os.urandom(16)
		pin_hash = _hash_pin(pin, pin_salt) if pin else b""

		#store the PIN salt, hash, and flag in meta table. 
		conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)",
			("pin_salt", base64.b64encode(pin_salt).decode()))
		conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)",
			("pin_hash", base64.b64encode(pin_hash).decode()))
		conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)",
			("pin_enabled", "True" if pin else "False"))
  
		# Challenge question
		answer_salt = os.urandom(16)
		answer_hash = _hash_answer(challenge_answer, answer_salt) if challenge_answer else b""

		#store the challenge question, answer salt, answer hash, and flag in meta table.
		conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)",
			("challenge_question", challenge_question or ""))
		conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)",
			("challenge_answer_salt", base64.b64encode(answer_salt).decode()))
		conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)",
			("challenge_answer_hash", base64.b64encode(answer_hash).decode()))
		conn.execute("INSERT INTO meta (key, value) VALUES (?, ?)",
			("challenge_enabled", "True" if challenge_answer else "False"))

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

def is_pin_enabled(db_path: str) -> bool:
	try:
		meta = _load_meta(db_path)
		return meta.get("pin_enabled", "False") == "True"
	except Exception:
		return False

def is_challenge_enabled(db_path: str) -> bool:
	try:
		meta = _load_meta(db_path)
		return meta.get("challenge_enabled", "False") == "True"
	except Exception:
		return False

def generate_2fa_secret() -> str:
	"""Generate a new 2FA secret for Google Authenticator"""
	return pyotp.random_base32()

def get_2fa_qr_code(secret: str, username: str = "Enclav3") -> str:
	"""Generate a QR code image as base64 string for 2FA setup"""
	totp = pyotp.TOTP(secret)
	provisioning_uri = totp.provisioning_uri(name=username, issuer_name="Enclav3")
	qr = qrcode.QRCode(version=1, box_size=10, border=5)
	qr.add_data(provisioning_uri)
	qr.make(fit=True)
	img = qr.make_image(fill_color="black", back_color="white")
	img_io = BytesIO()
	img.save(img_io, 'PNG')
	img_io.seek(0)
	img_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')
	return img_base64

def verify_totp(secret: str, token: str, window: int = 1) -> bool:
	"""Verify a TOTP token against the secret"""
	if not secret or not token:
		return False
	try:
		totp = pyotp.TOTP(secret)
		return totp.verify(token, valid_window=window)
	except Exception:
		return False

def enable_2fa(db_path: str, master_password: str, secret: str) -> None:
	"""Enable 2FA for the user"""
	_load_master_key(db_path, master_password)
	
	with _get_connection(db_path) as conn:
		conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("2fa_enabled", "True"))
		conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("2fa_secret", secret))

def disable_2fa(db_path: str, master_password: str) -> None:
	"""Disable 2FA for the user"""
	_load_master_key(db_path, master_password)
	
	with _get_connection(db_path) as conn:
		conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("2fa_enabled", "False"))
		conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("2fa_secret", ""))

def is_2fa_enabled(db_path: str) -> bool:
	"""Check if 2FA is enabled for the user"""
	try:
		meta = _load_meta(db_path)
		return meta.get("2fa_enabled", "False") == "True"
	except Exception:
		return False

def get_2fa_secret(db_path: str) -> str:
	"""Get the 2FA secret from the database"""
	try:
		meta = _load_meta(db_path)
		return meta.get("2fa_secret", "")
	except Exception:
		return ""

def update_security_settings(db_path: str, master_password: str,
                              pin: Optional[str] = None,
                              challenge_question: Optional[str] = None,
                              challenge_answer: Optional[str] = None) -> None:
	_load_master_key(db_path, master_password)

	with _get_connection(db_path) as conn:
		if pin is not None:
			pin_salt = os.urandom(16)
			pin_hash = _hash_pin(pin, pin_salt)
			conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
				("pin_salt", base64.b64encode(pin_salt).decode()))
			conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
				("pin_hash", base64.b64encode(pin_hash).decode()))
			conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
				("pin_enabled", "True"))

		if challenge_question and challenge_answer:
			answer_salt = os.urandom(16)
			answer_hash = _hash_answer(challenge_answer, answer_salt)
			conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
				("challenge_question", challenge_question))
			conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
				("challenge_answer_salt", base64.b64encode(answer_salt).decode()))
			conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
				("challenge_answer_hash", base64.b64encode(answer_hash).decode()))
			conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
				("challenge_enabled", "True"))
def add_entry(db_path: str, entry: Entry, master_password: str) -> None: #Add a new password entry to the database, encrypting the password and username using the tier-specific key derived from the master password
	meta = _load_meta(db_path)
	
	# Get tier-specific salt and iterations
	tier_salt_key = _tier_salt_key(entry.tier)
	tier_iter_key = _tier_iterations_key(entry.tier)
	tier_salt = base64.b64decode(meta[tier_salt_key])
	tier_iterations = int(meta[tier_iter_key])
	
	# Derive encryption key using master password and tier-specific parameters
	encryption_key = _derive_key(master_password, tier_salt, tier_iterations)
	cipher = Fernet(encryption_key)
	encrypted_password = cipher.encrypt(entry.password.encode('utf-8')).decode('utf-8')
	encrypted_username = cipher.encrypt(entry.username.encode('utf-8')).decode('utf-8')
	
	with _get_connection(db_path) as conn:
		conn.execute( #Add the new entry to the entries table, storing the site, encrypted username, encrypted password, notes, and creation timestamp
			"""
			INSERT INTO entries (site, username, password_enc, notes, created_at, tier)
			VALUES (?, ?, ?, ?, ?, ?)
			""",
			(entry.site, encrypted_username, encrypted_password, entry.notes, _utc_now(), entry.tier),
		)

def list_entries(db_path: str, master_password: str, sort: str = "alpha") -> list[dict[str, str]]: #List all entries in the database, decrypting passwords and usernames using the master password
	# sorting logic
	if sort == "alpha":
		order_clause = "ORDER BY site ASC"
	
	elif sort == "newest":
		order_clause = "ORDER BY created_at DESC"

	elif sort == "oldest":
		order_clause = "ORDER BY created_at ASC"

	else:
		order_clause = "ORDER BY site ASC"

	meta = _load_meta(db_path)
	
	with _get_connection(db_path) as conn:
		rows = conn.execute(
			f"SELECT id, site, username, password_enc, notes, created_at, tier FROM entries {order_clause}"
		).fetchall()
		
	entries: list[dict[str, str]] = []
	for row in rows:
		entry_id, site, username_enc, password_enc, notes, created_at, tier = row
		
		# Decrypt password and username using tier-specific salt and iterations with master password
		tier_salt_key = _tier_salt_key(tier)
		tier_iter_key = _tier_iterations_key(tier)
		tier_salt = base64.b64decode(meta[tier_salt_key])
		tier_iterations = int(meta[tier_iter_key])
		
		try:
			# Derive key using master password and tier-specific parameters
			encryption_key = _derive_key(master_password, tier_salt, tier_iterations)
			cipher = Fernet(encryption_key)
			decrypted_password = cipher.decrypt(password_enc.encode('utf-8')).decode('utf-8')
			decrypted_username = cipher.decrypt(username_enc.encode('utf-8')).decode('utf-8')
			display_password = decrypted_password
			display_username = decrypted_username
		except (InvalidToken, Exception):
			display_password = "[Unable to decrypt]"
			display_username = "[Unable to decrypt]"
		
		entries.append(
			{
				"id": str(entry_id),
				"site": site,
				"username": display_username,
				"password": display_password,
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

#edit entries function. 
def edit_entry(db_path: str, master_password: str, entry_id: int, site: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, notes: Optional[str] = None, tier: Optional[str] = None) -> None:
	_load_master_key(db_path, master_password)
	meta = _load_meta(db_path)

	# get tier-specific salt and iterations
	tier_salt_key = _tier_salt_key(tier)
	tier_iter_key = _tier_iterations_key(tier)
	tier_salt = base64.b64decode(meta[tier_salt_key])
	tier_iterations = int(meta[tier_iter_key])

	# derive encryption key using master password and tier-specific parameters
	encryption_key = _derive_key(master_password, tier_salt, tier_iterations)
	cipher = Fernet(encryption_key)
	encrypted_password = cipher.encrypt(password.encode('utf-8')).decode('utf-8')
	encrypted_username = cipher.encrypt(username.encode('utf-8')).decode('utf-8')

	#updates entries in the database
	with _get_connection(db_path) as conn:
		cur = conn.execute(
			"UPDATE entries SET site=?, username=?, password_enc=?, notes=?, tier=? WHERE id=?",
			(site, encrypted_username, encrypted_password, notes, tier, entry_id),
		)
		if cur.rowcount == 0:
			print("Entry not found.")

def export_passwords(db_path: str, master_password: str) -> str:
    """Export all password entries to a CSV string."""
    entries = list_entries(db_path, master_password)
    
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["name", "url", "username", "password", "note"],
        extrasaction="ignore"
    )
    writer.writeheader()
    
    for e in entries:
        writer.writerow({
            "name":     e["site"],
            "url":      e["site"],
            "username": e["username"],
            "password": e["password"],
            "note":     e["notes"],
        })
    
    return output.getvalue()

# ---------------------------------------------------------------------------
# Vault file functions – files are always encrypted at the "high" (Tier 3)
# security level, so they share the same encryption strength as Tier 3 passwords.
# ---------------------------------------------------------------------------

def _vault_cipher(db_path: str, master_password: str) -> "Fernet":
	"""Return a Fernet cipher keyed with the Tier-3 (high) derived key."""
	meta = _load_meta(db_path)
	tier_salt = base64.b64decode(meta[_tier_salt_key("high")])
	tier_iterations = int(meta[_tier_iterations_key("high")])
	encryption_key = _derive_key(master_password, tier_salt, tier_iterations)
	return Fernet(encryption_key)


def add_vault_file(db_path: str, master_password: str, filename: str,
                   mime_type: str, file_bytes: bytes, notes: Optional[str] = None) -> None:
	"""Encrypt and store a file in the vault (always Tier-3 encryption)."""
	_load_master_key(db_path, master_password)  # verify master password first
	cipher = _vault_cipher(db_path, master_password)
	encrypted_data = cipher.encrypt(file_bytes).decode("utf-8")
	with _get_connection(db_path) as conn:
		conn.execute(
			"""
			INSERT INTO vault_files (filename, mime_type, file_data_enc, notes, created_at)
			VALUES (?, ?, ?, ?, ?)
			""",
			(filename, mime_type, encrypted_data, notes, _utc_now()),
		)


def list_vault_files(db_path: str, master_password: str) -> list[dict]:
	"""Return metadata for all vault files (no decrypted binary data)."""
	_load_master_key(db_path, master_password)
	with _get_connection(db_path) as conn:
		rows = conn.execute(
			"SELECT id, filename, mime_type, notes, created_at FROM vault_files ORDER BY created_at DESC"
		).fetchall()
	return [
		{"id": str(r[0]), "filename": r[1], "mime_type": r[2],
		 "notes": r[3] or "", "created_at": r[4]}
		for r in rows
	]


def get_vault_file(db_path: str, master_password: str, file_id: int) -> dict:
	"""Decrypt and return a vault file's bytes plus metadata."""
	_load_master_key(db_path, master_password)
	with _get_connection(db_path) as conn:
		row = conn.execute(
			"SELECT filename, mime_type, file_data_enc, notes FROM vault_files WHERE id = ?",
			(file_id,),
		).fetchone()
	if row is None:
		raise RuntimeError("Vault file not found.")
	filename, mime_type, file_data_enc, notes = row
	cipher = _vault_cipher(db_path, master_password)
	try:
		file_bytes = cipher.decrypt(file_data_enc.encode("utf-8"))
	except (InvalidToken, Exception) as exc:
		raise RuntimeError("Unable to decrypt vault file – wrong master password?") from exc
	return {"filename": filename, "mime_type": mime_type,
	        "file_bytes": file_bytes, "notes": notes or ""}


def delete_vault_file(db_path: str, master_password: str, file_id: int) -> None:
	"""Delete a vault file by ID."""
	_load_master_key(db_path, master_password)
	with _get_connection(db_path) as conn:
		cur = conn.execute("DELETE FROM vault_files WHERE id = ?", (file_id,))
		if cur.rowcount == 0:
			raise RuntimeError("Vault file not found.")


def migrate_add_vault_table(db_path: str) -> None:
	"""Idempotently add the vault_files table to an existing, initialized database.
	Does nothing if the database file doesn't exist or hasn't been initialized yet."""
	if not os.path.exists(db_path):
		return  # DB not created yet; init_db will create the table instead
	with _get_connection(db_path) as conn:
		# Only migrate if the DB has already been initialized (meta table exists)
		has_meta = conn.execute(
			"SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
		).fetchone()
		if not has_meta:
			return  # Empty/uninitialized file — leave it alone
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS vault_files (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				filename TEXT NOT NULL,
				mime_type TEXT NOT NULL,
				file_data_enc TEXT NOT NULL,
				notes TEXT,
				created_at TEXT NOT NULL
			)
			"""
		)


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
		add_entry(db_path, entry, master_password)
		print("Entry added.")
		return

	if args.command == "list": #list all entries
		entries = list_entries(db_path, master_password)
		for entry in entries:
			print(f"ID: {entry['id']}, Site: {entry['site']}, Username: {entry['username']}, Tier: {entry['tier']}")
		return

	if args.command == "delete": #Delete an entry by ID
		delete_entry(db_path, master_password, args.id)
		return

if __name__ == "__main__":
	main()