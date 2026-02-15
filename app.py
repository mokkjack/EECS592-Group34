from flask import Flask, render_template, request, redirect, url_for, session, flash

import backend
from backend import Entry

app = Flask(__name__)
app.secret_key = "dev-secret-key"

DB_PATH = backend.DEFAULT_DB

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        master_password = request.form.get("master_password", "").strip()
        if not master_password:
            error = "Master password is required."
        else:
            try:
                backend.verify_master_password(DB_PATH, master_password)
            except RuntimeError as exc:
                error = str(exc)
            else:
                session["master_password"] = master_password
                return redirect(url_for("main"))
    return render_template("login.html", error=error)

@app.route("/main")
def main():
    if "master_password" not in session:
        return redirect(url_for("login"))
    try:
        entries = backend.list_entries_decrypted(DB_PATH, session["master_password"])
    except RuntimeError as exc:
        flash(str(exc))
        entries = []
    return render_template("main.html", entries=entries)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        master_password = request.form.get("master_password", "").strip()
        confirm = request.form.get("confirm_master_password", "").strip()
        if not master_password:
            error = "Master password is required."
        elif master_password != confirm:
            error = "Passwords do not match."
        else:
            try:
                backend.init_db(DB_PATH, master_password)
            except RuntimeError as exc:
                error = str(exc)
            else:
                session["master_password"] = master_password
                flash("Master password created.")
                return redirect(url_for("main"))
    return render_template("signup.html", error=error)


@app.route("/add-entry", methods=["POST"])
def add_entry():
    master_password = session.get("master_password")
    if not master_password:
        return redirect(url_for("login"))

    site = request.form.get("site", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    notes = request.form.get("notes", "").strip() or None
    tier = request.form.get("option", "").strip() or 1 # use 'tier' for selecting what database

    if not site or not username or not password:
        flash("Site, username, and password are required.")
        return redirect(url_for("main"))

    try:
        backend.add_entry(DB_PATH, master_password, Entry(site=site, username=username, password=password, notes=notes))
    except RuntimeError as exc:
        flash(str(exc))
    else:
        flash("Entry added.")

    return redirect(url_for("main"))


@app.route("/logout")
def logout():
    session.pop("master_password", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)