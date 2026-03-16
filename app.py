'''
Name: app.py
Authors: Jack Morice, Nick Grieco, Alex Carrillo, Gunther Luechtefield
Description: This file contains the Flask implementation, and defines routes for CRUD operations on password entries, as well as authentication.
It also sets up the desktop application using pywebview, running the Flask server in a separate thread to serve the web interface.
Inputs: User interactions with the web interface (login, signup, add entry, logout)
Outputs: Rendered HTML pages for login, signup, and main page with password entries; flash messages for errors and confirmations
Resources: ChatGPT was used in the pywebview integration.
'''
import threading
import time

import webview
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.serving import make_server
from io import BytesIO
import mimetypes

import backend
from backend import Entry

app = Flask(__name__)
app.secret_key = "dev-secret-key"

# Jinja2 filter: map a filename extension to a display emoji
def _vault_icon(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    icons = {
        "pdf": "📄", "doc": "📝", "docx": "📝", "xls": "📊", "xlsx": "📊",
        "ppt": "📑", "pptx": "📑", "txt": "📃", "md": "📃", "csv": "📊",
        "json": "🗂️", "xml": "🗂️", "zip": "📦", "tar": "📦", "gz": "📦",
        "png": "🖼️", "jpg": "🖼️", "jpeg": "🖼️", "gif": "🖼️",
        "webp": "🖼️", "bmp": "🖼️",
        "mp4": "🎬", "mov": "🎬", "mp3": "🎵", "wav": "🎵",
    }
    return icons.get(ext, "📁")

app.jinja_env.filters["vault_icon"] = _vault_icon

DB_PATH = backend.DEFAULT_DB

# ---------------------------------------------------------------------------
# Ensure the vault_files table exists even on databases created before the
# vault feature was added.
# ---------------------------------------------------------------------------
try:
    backend.migrate_add_vault_table(DB_PATH)
except Exception:
    pass  # DB may not exist yet (first run); init_db will create the table.

@app.route("/", methods=["GET", "POST"]) # Login page
def login(): #Login page handler
    error = None
    if request.method == "POST": #If it's a POST request, we need to verify the master password
        master_password = request.form.get("master_password", "").strip() #Get the master password from the form and strip whitespace
        if not master_password: #Error handling if the master password is empty
            error = "Master password is required." #Set the error message to "Master password is required."
        else: #otherwise
            try: #verify the master password using the backend function
                backend.verify_master_password(DB_PATH, master_password)
            except RuntimeError as exc: #Raise an error if the master password is incorrect
                error = str(exc)
            else: #If the master password is correct, check if 2FA is enabled
                if backend.is_2fa_enabled(DB_PATH):
                    # 2FA is enabled, redirect to 2FA verification page
                    session["master_password_temp"] = master_password
                    return redirect(url_for("verify_2fa"))
                else:
                    # 2FA is not enabled, login directly
                    session["master_password"] = master_password
                    return redirect(url_for("main"))
    return render_template("login.html", error=error) #Render the login page with any error messages

@app.route("/main") #Main page handler
def main(): #If the master password is not in the session, redirect to the login page
    if "master_password" not in session: #If the master password is not in the session, redirect to the login page
        return redirect(url_for("login")) #Redirect to the login page

    try: #Get all passwords
        sort = request.args.get("sort", "alpha")
        entries = backend.list_entries(DB_PATH, session["master_password"], sort)
        
    except RuntimeError as exc: #Error handling
        flash(str(exc))
        entries = []

    # tier filtering
    tier1_entries = [e for e in entries if e.get("tier") == "low"]
    tier2_entries = [e for e in entries if e.get("tier") == "medium"]
    tier3_entries = [e for e in entries if e.get("tier") == "high"]
        
    # Check if 2FA is enabled for viewing tier 2 and 3 entries
    two_fa_enabled = backend.is_2fa_enabled(DB_PATH)
    vault_files = []
    if two_fa_enabled:
        try:
            backend.migrate_add_vault_table(DB_PATH)
            vault_files = backend.list_vault_files(DB_PATH, session["master_password"])
            print(f"[vault] loaded {len(vault_files)} file(s)")
        except Exception as exc:
            print(f"[vault] ERROR loading files: {exc}")
            flash(f"Vault error: {exc}")
            vault_files = []

    if not two_fa_enabled:
        tier2_entries = []  # Hide tier 2 entries if 2FA not enabled
        tier3_entries = []  # Hide tier 3 entries if 2FA not enabled
        if len([e for e in entries if e.get("tier") in ["medium", "high"]]) > 0:
            flash("Tier 2 and 3 entries require 2FA to be enabled. Please enable 2FA in settings.")
    
    print(f"Tier1 entries: {[e['id'] for e in tier1_entries]}")
    return render_template("main.html", entries=entries, tier1_entries=tier1_entries,
                           tier2_entries=tier2_entries, tier3_entries=tier3_entries,
                           two_fa_enabled=two_fa_enabled, vault_files=vault_files,
                           sort=sort) #Render the main page with the decrypted entries
@app.route("/signup", methods=["GET", "POST"]) #Signup page handler
def signup(): #Signing up for a new master password
    error = None
    if request.method == "POST": #If it's a POST request, we need to create a new master password
        master_password = request.form.get("master_password", "").strip() #Get the master password from the form and strip whitespace
        confirm = request.form.get("confirm_master_password", "").strip() #Get the confirm master password from the form and strip whitespace
        if not master_password: #handling empty password
            error = "Master password is required."
        elif master_password != confirm: #handling password confirmation mismatch
            error = "Passwords do not match." #Error handling
        else: #If the master password is valid and matches the confirmation, try to initialize the database with the new master password
            try: #Initialize the database with the new master password using the backend function
                backend.init_db(DB_PATH, master_password)
            except RuntimeError as exc: #Raise an error if the database already exists or if there was an issue creating it
                error = str(exc)
            else: #If the database was successfully initialized, store the master password in the session and redirect to the main page
                session["master_password"] = master_password #Store the master password in the session
                flash("Master password created.") #Flash a message indicating that the master password was created
                return redirect(url_for("main")) #Redirect to the main page
    return render_template("signup.html", error=error) #Render the signup page with any error messages


@app.route("/add-entry", methods=["POST"])
def add_entry(): #Add password entry handler
    master_password = session.get("master_password") #Get the master password from the session
    if not master_password: #If the master password is not in the session, redirect to the login page
        return redirect(url_for("login"))

    site = request.form.get("site", "").strip() #Get the site from the form and strip whitespace
    username = request.form.get("username", "").strip() #Get the username from the form and strip whitespace
    password = request.form.get("password", "").strip() #Get the password from the form and strip whitespace
    notes = request.form.get("notes", "").strip() or None #Get the notes from the form, strip whitespace, and set to None if empty
    tier = request.form.get("option", "").strip() or backend.DEFAULT_TIER # use 'tier' for selecting what database
    
    if not site or not username or not password: #If any of the required fields (site, username, password) are empty, flash an error message and redirect to the main page
        flash("Site, username, and password are required.")
        return redirect(url_for("main"))

    try: #Try to add the new entry using the backend function, encrypting it with the master password from the session
        backend.add_entry(DB_PATH, Entry(site=site, username=username, password=password, notes=notes, tier=tier), master_password)
    except RuntimeError as exc:
        flash(str(exc))
    else:
        flash("Entry added.")

    return redirect(url_for("main")) #Redirect to the main page after adding the entry


@app.route("/delete-entry/<int:entry_id>", methods=["POST"])
def delete_entry(entry_id: int): #Delete password entry handler
    master_password = session.get("master_password") 
    if not master_password:
        return redirect(url_for("login"))
    try:
        backend.delete_entry(DB_PATH, master_password, entry_id) #Try to delete the entry with the given ID using the backend function
    except RuntimeError as exc:
        flash(str(exc))
    else:
        flash("Entry deleted.")

    return redirect(url_for("main"))

@app.route("/edit-entry/<int:entry_id>", methods=["POST"])
def edit_entry(entry_id: int): #edit password entry handler
    master_password = session.get("master_password")
    if not master_password: #if the master password is not in the session, redirect to the login page
        return redirect(url_for("login"))
    site = request.form.get("site", "").strip() #get the site from the form and strip whitespace
    username = request.form.get("username", "").strip() #get the username from the form and strip whitespace
    password = request.form.get("password", "").strip() #get the password from the form and strip whitespace
    notes = request.form.get("notes", "").strip() or None
    tier = request.form.get("tier", "").strip() or backend.DEFAULT_TIER #allows you to change tier of entry

    #error handling for empty required fields (site, username, password)
    if not site or not username or not password:
        flash("Site, username, and password are required.")
        return redirect(url_for("main"))

    #try to edit the entry with the given ID
    try:
        backend.edit_entry(DB_PATH, master_password, entry_id, site, username, password, notes, tier)
    except RuntimeError as exc:
        flash(str(exc))
    else:
        flash("Entry updated.")
    return redirect(url_for("main"))

#route for setting up a PIN code for quick access to the application, stored securely in the database
@app.route("/setup-pin", methods=["POST"])
def setup_pin():
    if "master_password" not in session:
        return redirect(url_for("login"))
    
    pin = request.form.get("pin", "").strip() # get the PIN from the form and strip whitespace
    confirm_pin = request.form.get("confirm_pin", "").strip()  # get the confirm PIN from the form

    if not pin:
        flash("PIN is required.")
        return redirect(url_for("settings"))

    if pin != confirm_pin:  # if the two PIN fields don't match flash an error and redirect back to settings
        flash("PINs do not match.")
        return redirect(url_for("settings"))
    
    # save the PIN using the backend function, which hashes it before storing
    try:
        backend.update_security_settings(DB_PATH, session["master_password"], pin=pin)
        flash("PIN set up successfully.")
    except RuntimeError as exc:
        flash(str(exc))
    
    return redirect(url_for("settings"))

#route for setting up challenge question and answer for account recovery
@app.route("/setup-challenge", methods=["POST"])
def setup_challenge():
    if "master_password" not in session:
        return redirect(url_for("login"))
    
    question = request.form.get("challenge_question", "").strip()
    answer = request.form.get("challenge_answer", "").strip()
    
    if not question or not answer:
        flash("Both a question and answer are required.")
        return redirect(url_for("settings"))
    
    # save the question and hashed answer using the backend function
    try:
        backend.update_security_settings(DB_PATH, session["master_password"], 
                                         challenge_question=question, 
                                         challenge_answer=answer)
        flash("Challenge question set up successfully.")
    except RuntimeError as exc:
        flash(str(exc))
    
    return redirect(url_for("settings"))

@app.route("/logout")
def logout(): #Logout handler
    session.pop("master_password", None)
    return redirect(url_for("login"))

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """Verify 2FA token during login"""
    if "master_password_temp" not in session:
        return redirect(url_for("login"))
    
    error = None
    if request.method == "POST":
        totp_code = request.form.get("totp_code", "").strip()
        if not totp_code:
            error = "2FA code is required."
        else:
            secret = backend.get_2fa_secret(DB_PATH)
            if backend.verify_totp(secret, totp_code):
                # Verification successful, set the master password in session
                session["master_password"] = session.pop("master_password_temp")
                flash("2FA verification successful.")
                return redirect(url_for("main"))
            else:
                error = "Invalid 2FA code. Please try again."
    
    return render_template("verify_2fa.html", error=error)

@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    """Setup 2FA for the user"""
    if "master_password" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        # Generate a new secret and redirect to setup page
        secret = backend.generate_2fa_secret()
        session["2fa_secret_temp"] = secret
        return redirect(url_for("confirm_2fa_setup"))
    
    return redirect(url_for("settings"))

@app.route("/confirm-2fa-setup", methods=["GET", "POST"])
def confirm_2fa_setup():
    """Confirm 2FA setup with a verification code"""
    if "master_password" not in session:
        return redirect(url_for("login"))
    
    if "2fa_secret_temp" not in session:
        flash("2FA setup not initiated.")
        return redirect(url_for("settings"))
    
    secret = session["2fa_secret_temp"]
    error = None
    
    if request.method == "POST":
        totp_code = request.form.get("totp_code", "").strip()
        if not totp_code:
            error = "2FA code is required."
        else:
            if backend.verify_totp(secret, totp_code):
                # Verification successful, enable 2FA
                try:
                    backend.enable_2fa(DB_PATH, session["master_password"], secret)
                    session.pop("2fa_secret_temp", None)
                    flash("2FA has been successfully enabled!")
                    return redirect(url_for("settings"))
                except Exception as exc:
                    error = f"Failed to enable 2FA: {str(exc)}"
            else:
                error = "Invalid 2FA code. Please try again."
    
    qr_code_base64 = backend.get_2fa_qr_code(secret)
    return render_template("setup_2fa.html", qr_code=qr_code_base64, secret=secret, error=error)

@app.route("/disable-2fa", methods=["POST"])
def disable_2fa():
    """Disable 2FA for the user"""
    if "master_password" not in session:
        return redirect(url_for("login"))
    
    try:
        backend.disable_2fa(DB_PATH, session["master_password"])
        flash("2FA has been disabled.")
    except Exception as exc:
        flash(f"Failed to disable 2FA: {str(exc)}")
    
    return redirect(url_for("settings"))

# ---------------------------------------------------------------------------
# Vault routes – only accessible when 2FA is enabled (same gate as Tier 3)
# ---------------------------------------------------------------------------

# 50 MB max upload size
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp", "bmp",  # images
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",  # documents
    "txt", "md", "csv", "json", "xml",  # text
    "zip", "tar", "gz",  # archives
    "mp4", "mov", "mp3", "wav",  # media
}


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/vault/upload", methods=["POST"])
def vault_upload():
    """Upload and encrypt a file into the Tier-3 vault."""
    master_password = session.get("master_password")
    if not master_password:
        return redirect(url_for("login"))
    if not backend.is_2fa_enabled(DB_PATH):
        flash("Vault requires 2FA to be enabled.")
        return redirect(url_for("main"))

    file = request.files.get("vault_file")
    notes = request.form.get("vault_notes", "").strip() or None

    if not file or file.filename == "":
        flash("No file selected.")
        return redirect(url_for("main"))
    if not _allowed_file(file.filename):
        flash("File type not allowed.")
        return redirect(url_for("main"))

    filename = file.filename
    file_bytes = file.read()
    mime_type = file.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"

    try:
        backend.add_vault_file(DB_PATH, master_password, filename, mime_type, file_bytes, notes)
        print(f"[vault] saved '{filename}' ({len(file_bytes)} bytes)")
        flash(f"'{filename}' added to vault.")
    except Exception as exc:
        print(f"[vault] upload ERROR: {exc}")
        flash(f"Vault upload error: {exc}")

    return redirect(url_for("main") + "#tier3")


@app.route("/vault/download/<int:file_id>")
def vault_download(file_id: int):
    """Decrypt and stream a vault file back to the user."""
    master_password = session.get("master_password")
    if not master_password:
        return redirect(url_for("login"))
    if not backend.is_2fa_enabled(DB_PATH):
        flash("Vault requires 2FA to be enabled.")
        return redirect(url_for("main"))

    try:
        vault_file = backend.get_vault_file(DB_PATH, master_password, file_id)
    except RuntimeError as exc:
        flash(str(exc))
        return redirect(url_for("main"))

    return send_file(
        BytesIO(vault_file["file_bytes"]),
        mimetype=vault_file["mime_type"],
        as_attachment=True,
        download_name=vault_file["filename"],
    )


@app.route("/vault/delete/<int:file_id>", methods=["POST"])
def vault_delete(file_id: int):
    """Delete a vault file."""
    master_password = session.get("master_password")
    if not master_password:
        return redirect(url_for("login"))
    if not backend.is_2fa_enabled(DB_PATH):
        flash("Vault requires 2FA to be enabled.")
        return redirect(url_for("main"))

    try:
        backend.delete_vault_file(DB_PATH, master_password, file_id)
        flash("Vault file deleted.")
    except RuntimeError as exc:
        flash(str(exc))

    return redirect(url_for("main") + "#tier3")


def _run_flask_server() -> None: #Create a function to run the Flask server
    server = make_server("127.0.0.1", 5000, app)
    server.serve_forever()


def _run_desktop() -> None: #Create a function to run the desktop application using pywebview
    flask_thread = threading.Thread(target=_run_flask_server, daemon=True)
    flask_thread.start()
    time.sleep(0.5)
    webview.create_window("Enclav3", "http://127.0.0.1:5000", width=1100, height=700)
    webview.start()

@app.route("/settings")
def settings():
    if "master_password" not in session:
        return redirect(url_for("login"))
    two_fa_enabled = backend.is_2fa_enabled(DB_PATH)
    pin_enabled = backend.is_pin_enabled(DB_PATH)
    challenge_enabled = backend.is_challenge_enabled(DB_PATH)
    return render_template("settings.html", two_fa_enabled=two_fa_enabled,
                           pin_enabled=pin_enabled, challenge_enabled=challenge_enabled)

if __name__ == "__main__":
    _run_desktop()