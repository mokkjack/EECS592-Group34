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
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.serving import make_server

import backend
from backend import Entry

app = Flask(__name__)
app.secret_key = "dev-secret-key"

DB_PATH = backend.DEFAULT_DB

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
            else: #If the master password is correct, store it in the session and redirect to the main page
                session["master_password"] = master_password #Store the master password in the session
                return redirect(url_for("main")) #Redirect to the main page
    return render_template("login.html", error=error) #Render the login page with any error messages

@app.route("/main") #Main page handler
def main(): #If the master password is not in the session, redirect to the login page
    if "master_password" not in session: #If the master password is not in the session, redirect to the login page
        return redirect(url_for("login")) #Redirect to the login page
    try: #Get all passwords
        entries = backend.list_entries(DB_PATH)
    except RuntimeError as exc: #Error handling
        flash(str(exc))
        entries = []
    tier1_entries = [e for e in entries if e.get("tier") == "low"]
    tier2_entries = [e for e in entries if e.get("tier") == "medium"]
    tier3_entries = [e for e in entries if e.get("tier") == "high"]
    return render_template("main.html", entries=entries, tier1_entries=tier1_entries, tier2_entries=tier2_entries, tier3_entries=tier3_entries) #Render the main page with the decrypted entries

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
        backend.add_entry(DB_PATH, Entry(site=site, username=username, password=password, notes=notes, tier=tier))
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


@app.route("/logout")
def logout(): #Logout handler
    session.pop("master_password", None)
    return redirect(url_for("login"))

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
    return render_template("settings.html")

if __name__ == "__main__":
    _run_desktop()