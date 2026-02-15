# ENCLAV3

A Multitiered password manager and data vault

## Description

ENCLAV3 strives to be more than only a password manager. With multple tiers of protection to ensure that no matter what type of file or information needs to be stored it will remian protected. The lowest tier acts a a basic password manager, allowing the user to store passwords from different websites.The highest tier gives access to ENCLAV3's data vault. Giving the user the ability to store images, documents, and other sensitive or personal files into the secured vault.

## Features
- Local, encrypted password vault (SQLite)
- Three security tiers with different key-derivation strength
- Desktop UI powered by pywebview
- Simple add/view workflow with optional notes

## Requirements
- Python 3.10+ recommended
- pip

Python dependencies are listed in [requirements.txt](requirements.txt).

## Quick Start (Build the Desktop App)
Run the installer script and select your OS:

```
./install.sh
```

This installs dependencies (if needed) and produces a standalone build using PyInstaller. The output will be placed under the dist directory (created by PyInstaller).

## Run From Source (Development)
If you want to run the app directly without building:

```
python -m pip install -r requirements.txt
python app.py
```

The app launches a local Flask server and opens a desktop window.

## Project Structure
- [app.py](app.py): Flask routes and desktop app startup
- [backend.py](backend.py): Database and encryption logic
- [templates](templates): HTML views
- [static](static): CSS assets
- [install.sh](install.sh): Cross-platform build script

## Notes
- The database is stored in the user’s application data folder under an Enclav3 directory.
- If you forget your master password, encrypted entries cannot be recovered.