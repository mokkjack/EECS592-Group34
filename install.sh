#!/bin/bash

set -e

echo "Select your operating system:"
echo "1) Windows"
echo "2) macOS"
echo "3) Linux"
echo ""
read -p "Enter choice (1, 2, or 3): " choice

install_python_deps_unix() {
    local python_cmd="$1"
    if ! command -v "$python_cmd" >/dev/null 2>&1; then
        echo "${python_cmd} not found. Please install Python 3 and try again."
        exit 1
    fi
    "$python_cmd" -m pip install --upgrade pip
    "$python_cmd" -m pip install -r requirements.txt
    "$python_cmd" -m pip install pyinstaller pywebview
}

if [ "$choice" = "1" ]; then
    echo "Running Windows installation..."
    # Git Bash / WSL context: run Windows python + pip + PyInstaller via PowerShell
    powershell.exe -NoProfile -Command "python -m pip install --upgrade pip; python -m pip install -r requirements.txt; python -m pip install pyinstaller; python -m PyInstaller --onefile --noconsole --name Enclav3 --add-data 'templates;templates' --add-data 'static;static' app.py"

elif [ "$choice" = "2" ]; then
    echo "Running macOS installation..."
    install_python_deps_unix "python3"
    python3 -m PyInstaller --onefile --noconsole --name Enclav3 --add-data "templates:templates" --add-data "static:static" app.py

elif [ "$choice" = "3" ]; then
    echo "Running Linux installation..."
    install_python_deps_unix "python3"
    python3 -m PyInstaller --onefile --noconsole --name Enclav3 --add-data "templates:templates" --add-data "static:static" app.py

else
    echo "Invalid selection. Please run the script again and choose 1, 2, or 3."
    exit 1
fi

echo "Installation process finished."
