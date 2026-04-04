@echo off
echo Trying Python 3...
python3 -m http.server 8000 2>nul
if errorlevel 1 (
  echo Trying Python...
  python -m http.server 8000 2>nul
)
if errorlevel 1 (
  echo Python not found. Install from https://www.python.org/downloads/
  pause
)
