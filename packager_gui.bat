@echo off
REM Open the Project Packager GUI for the current folder (no console window).
REM Copyright 2026 Leon Priest / 7h3v01d. Apache License 2.0.
where pythonw >nul 2>&1 && (start "" pythonw "%~dp0project_packager.py" gui "%CD%" & exit /b 0)
python "%~dp0project_packager.py" gui "%CD%"
