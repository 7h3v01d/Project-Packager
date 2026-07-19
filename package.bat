@echo off
setlocal EnableExtensions
title Project Packager

REM ============================================================================
REM  Project Packager - interactive menu
REM
REM  Drop this beside project_packager.py, or anywhere in a project that has
REM  the tool on PATH or in a parent folder. Double-click to run.
REM
REM  Copyright 2026 Leon Priest / 7h3v01d. Apache License 2.0.
REM ============================================================================

set "PROJECT=%CD%"
set "LASTZIP="

call :find_python
if errorlevel 1 goto :fatal

call :find_packager
if errorlevel 1 goto :fatal

REM ============================================================================
REM  Main menu
REM ============================================================================
:menu
cls
echo.
echo  ========================================================================
echo   PROJECT PACKAGER
echo  ========================================================================
echo   Project:  %PROJECT%
echo   Tool:     %PACKAGER%
echo  ------------------------------------------------------------------------
echo.
echo   BEFORE YOU SEND ANYTHING
echo     1.  Preview          Show what would be packaged. Changes nothing.
echo     2.  What's excluded  List every dropped file and the rule that did it.
echo.
echo   PACKAGE
echo     3.  Share            Clean ZIP for sending to someone.
echo     4.  Release          Strict. Runs checks, blocks on secrets.
echo     5.  Backup           Keeps almost everything, junk included.
echo     6.  Custom           Choose your own options.
echo.
echo   ARCHIVES
echo     7.  Verify           Check an archive against its manifest and hash.
echo.
echo   RELEASE GATES
echo     8.  Run checks       Test the project without packaging.
echo     9.  Set up config    Write starter release_check.toml + .packagerignore.
echo.
echo     H.  Help             What the profiles and exit codes mean.
echo     Q.  Quit
echo.
set "CHOICE="
set /p "CHOICE=  Select: "
if not defined CHOICE goto :menu

if /i "%CHOICE%"=="1" goto :preview
if /i "%CHOICE%"=="2" goto :excluded
if /i "%CHOICE%"=="3" goto :share
if /i "%CHOICE%"=="4" goto :release
if /i "%CHOICE%"=="5" goto :backup
if /i "%CHOICE%"=="6" goto :custom
if /i "%CHOICE%"=="7" goto :verify
if /i "%CHOICE%"=="8" goto :checks
if /i "%CHOICE%"=="9" goto :init
if /i "%CHOICE%"=="H" goto :help
if /i "%CHOICE%"=="Q" goto :quit
goto :menu

REM ============================================================================
REM  Actions
REM ============================================================================

:preview
call :banner "PREVIEW - nothing will be written or deleted"
"%PYTHON%" "%PACKAGER%" package "%PROJECT%" --dry-run --list-included
call :report %ERRORLEVEL%
goto :menu

:excluded
call :banner "EXCLUDED ITEMS - every dropped file, with the reason"
"%PYTHON%" "%PACKAGER%" package "%PROJECT%" --dry-run --list-excluded
call :report %ERRORLEVEL%
goto :menu

:share
call :banner "SHARE PACKAGE"
echo   Excludes caches, VCS data, virtualenvs, build output and session debris.
echo   Secrets are reported but do not block. Nothing is deleted.
echo.
call :ask_name
"%PYTHON%" "%PACKAGER%" package "%PROJECT%" %NAMEARG%
call :report %ERRORLEVEL%
if not errorlevel 1 call :offer_verify
goto :menu

:release
call :banner "RELEASE PACKAGE"
echo   Runs your release checks first, then packages.
echo   Applies strict privacy exclusions and deletes cache junk.
echo   REFUSES to package if it finds a secret, or a text file it could not
echo   read. Expect it to say no the first few times - that is the point.
echo.
call :confirm "Run release packaging"
if errorlevel 1 goto :menu
call :ask_name
"%PYTHON%" "%PACKAGER%" package "%PROJECT%" --profile release %NAMEARG%
call :report %ERRORLEVEL%
if not errorlevel 1 call :offer_verify
goto :menu

:backup
call :banner "BACKUP PACKAGE"
echo   Keeps almost everything, including .venv, build/, dist/ and databases.
echo   For archiving your own work, not for sending to anyone.
echo.
call :ask_name
"%PYTHON%" "%PACKAGER%" package "%PROJECT%" --profile backup %NAMEARG%
call :report %ERRORLEVEL%
goto :menu

:custom
cls
call :banner "CUSTOM PACKAGE"
set "ARGS="

echo   Profile:
echo     1. share    (default)
echo     2. release  (strict, runs checks, blocks on secrets)
echo     3. backup   (keeps almost everything)
echo.
set "P="
set /p "P=  Profile [1]: "
if "%P%"=="2" set "ARGS=%ARGS% --profile release"
if "%P%"=="3" set "ARGS=%ARGS% --profile backup"

echo.
set "NAME="
set /p "NAME=  ZIP base name (blank = folder name): "
if defined NAME set "ARGS=%ARGS% --name "%NAME%""

set "OUT="
set /p "OUT=  Output folder (blank = ..\packaged): "
if defined OUT set "ARGS=%ARGS% --output "%OUT%""

echo.
echo   Extra exclusions. One per prompt, blank line when done.
echo   Examples:  notes/     /scratch/     *.csv     data\raw\
:excl_loop
set "EX="
set /p "EX=    --exclude: "
if defined EX (
    set "ARGS=%ARGS% --exclude "%EX%""
    goto :excl_loop
)

echo.
echo   Force-include. Overrides exclusions, even inside excluded folders.
echo   Examples:  *.zip     .vscode/settings.json
:incl_loop
set "IN="
set /p "IN=    --include: "
if defined IN (
    set "ARGS=%ARGS% --include "%IN%""
    goto :incl_loop
)

echo.
call :yesno "Delete cache junk first (__pycache__, .pytest_cache, *.pyc)"
if not errorlevel 1 set "ARGS=%ARGS% --clean"

call :yesno "Run release checks first and abort if any fail"
if not errorlevel 1 set "ARGS=%ARGS% --check"

call :yesno "Replace an existing ZIP of the same name"
if not errorlevel 1 set "ARGS=%ARGS% --overwrite"

call :yesno "Dry run - show what would happen, write nothing"
if not errorlevel 1 set "ARGS=%ARGS% --dry-run"

echo.
echo  ------------------------------------------------------------------------
echo   Command:
echo     python project_packager.py package . %ARGS%
echo  ------------------------------------------------------------------------
echo.
call :confirm "Run this"
if errorlevel 1 goto :menu
echo.
"%PYTHON%" "%PACKAGER%" package "%PROJECT%" %ARGS%
call :report %ERRORLEVEL%
if not errorlevel 1 call :offer_verify
goto :menu

:verify
call :banner "VERIFY AN ARCHIVE"
echo   Re-hashes every member against the embedded manifest, and checks the
echo   ZIP against its .sha256 sidecar.
echo.
echo   Archives found nearby:
set "FOUND=0"
for %%F in ("%PROJECT%\..\packaged\*.zip") do (
    echo     %%~nxF
    set "FOUND=1"
)
for %%F in ("%PROJECT%\*.zip") do (
    echo     %%~nxF
    set "FOUND=1"
)
if "%FOUND%"=="0" echo     (none found - run a package first, or type a full path)
echo.
set "ZIP="
if defined LASTZIP (
    echo   Press Enter to verify the archive just created:
    echo     %LASTZIP%
    echo.
)
set /p "ZIP=  Archive path: "
if not defined ZIP set "ZIP=%LASTZIP%"
if not defined ZIP goto :menu
echo.
"%PYTHON%" "%PACKAGER%" verify "%ZIP%"
call :report %ERRORLEVEL%
goto :menu

:checks
call :banner "RELEASE CHECKS"
echo   Runs the built-in checks plus anything in release_check.toml.
echo   Packages nothing.
echo.
"%PYTHON%" "%PACKAGER%" check "%PROJECT%"
call :report %ERRORLEVEL%
goto :menu

:init
call :banner "SET UP CONFIG FILES"
echo   Writes starter release_check.toml and .packagerignore into this project.
echo   Existing files are not overwritten.
echo.
call :confirm "Write starter config here"
if errorlevel 1 goto :menu
"%PYTHON%" "%PACKAGER%" init "%PROJECT%"
call :report %ERRORLEVEL%
goto :menu

:help
cls
echo.
echo  ========================================================================
echo   HELP
echo  ========================================================================
echo.
echo   PROFILES
echo     share     Default. Drops caches, VCS data, virtualenvs, build output,
echo               session debris and existing ZIPs. Warns about secrets but
echo               still packages. Use this for sending code to someone.
echo.
echo     release   Everything share does, plus: runs your release checks first,
echo               deletes cache junk, applies extra privacy exclusions such as
echo               .env, and refuses to package if it finds a secret or a text
echo               file it could not read.
echo.
echo     backup    Keeps almost everything - .venv, build/, dist/, databases,
echo               logs. Only VCS metadata is dropped. For your own archives.
echo.
echo   EXIT CODES
echo      0   Success
echo      1   Checks failed, or verification found a problem
echo      2   Project path missing or not a directory
echo      3   Output ZIP already exists - use overwrite
echo      4   Write error, or archive has no verification evidence
echo      5   Secrets, or unscannable text, in strict/release mode
echo      6   Non-secret release checks failed
echo      7   Partial verification - hash matched, no manifest to check
echo      8   A project file collides with reserved PACKAGE_MANIFEST.json
echo      9   release_check.toml or .packagerignore present but unusable
echo     10   A source path escaped the project between scan and write
echo.
echo   WORTH KNOWING
echo     A refused command never modifies your project. No cleaning, no
echo     partial archives.
echo.
echo     Symlinks are never followed, not even with force-include. This is
echo     what stops a link quietly packaging something outside the project.
echo.
echo     Cleaning only ever removes cache junk. It will not touch .venv,
echo     build/, dist/, logs or databases.
echo.
echo     Replacement is not atomic yet. A failed write can destroy an existing
echo     archive, which is why release mode refuses overwrite without force.
echo.
pause
goto :menu

:quit
endlocal
exit /b 0

REM ============================================================================
REM  Helpers
REM ============================================================================

:banner
cls
echo.
echo  ========================================================================
echo   %~1
echo  ========================================================================
echo.
exit /b 0

:confirm
set "YN="
set /p "YN=  %~1? [y/N]: "
if /i "%YN%"=="y" exit /b 0
exit /b 1

:yesno
set "YN="
set /p "YN=  %~1? [y/N]: "
if /i "%YN%"=="y" exit /b 0
exit /b 1

:ask_name
set "NAMEARG="
set "NAME="
set /p "NAME=  ZIP base name (blank = folder name): "
if defined NAME set "NAMEARG=--name "%NAME%""
echo.
exit /b 0

:offer_verify
echo.
call :confirm "Verify the archive that was just created"
if errorlevel 1 exit /b 0
set "NEWEST="
for /f "delims=" %%F in ('dir /b /o-d "%PROJECT%\..\packaged\*.zip" 2^>nul') do (
    if not defined NEWEST set "NEWEST=%PROJECT%\..\packaged\%%F"
)
if not defined NEWEST (
    for /f "delims=" %%F in ('dir /b /o-d "%PROJECT%\*.zip" 2^>nul') do (
        if not defined NEWEST set "NEWEST=%PROJECT%\%%F"
    )
)
if not defined NEWEST (
    echo   Could not find the archive automatically.
    pause
    exit /b 0
)
set "LASTZIP=%NEWEST%"
echo.
"%PYTHON%" "%PACKAGER%" verify "%NEWEST%"
call :report %ERRORLEVEL%
exit /b 0

:report
echo.
echo  ------------------------------------------------------------------------
if "%~1"=="0"  echo   DONE - exit code 0
if "%~1"=="1"  echo   PROBLEM - exit code 1: checks failed, or verification found a fault
if "%~1"=="2"  echo   STOPPED - exit code 2: project path missing or not a directory
if "%~1"=="3"  echo   STOPPED - exit code 3: that ZIP already exists. Use a new name,
if "%~1"=="3"  echo            or enable overwrite under Custom.
if "%~1"=="4"  echo   STOPPED - exit code 4: write error, or no verification evidence
if "%~1"=="5"  echo   BLOCKED - exit code 5: secrets, or text that could not be scanned.
if "%~1"=="5"  echo            Nothing was packaged and nothing was deleted.
if "%~1"=="6"  echo   BLOCKED - exit code 6: release checks failed. Run option 8 for detail.
if "%~1"=="7"  echo   PARTIAL - exit code 7: hash matched, but no manifest to check against
if "%~1"=="8"  echo   STOPPED - exit code 8: a project file is named PACKAGE_MANIFEST.json.
if "%~1"=="8"  echo            Rename it - that name is reserved.
if "%~1"=="9"  echo   STOPPED - exit code 9: release_check.toml or .packagerignore is
if "%~1"=="9"  echo            present but unusable. Repair or remove it.
if "%~1"=="10" echo   STOPPED - exit code 10: a path escaped the project between scanning
if "%~1"=="10" echo            and writing. Nothing was archived.
echo  ------------------------------------------------------------------------
echo.
pause
exit /b 0

:find_python
set "PYTHON="
py -3 --version >nul 2>&1 && set "PYTHON=py -3"
if defined PYTHON exit /b 0
python --version >nul 2>&1 && set "PYTHON=python"
if defined PYTHON exit /b 0
echo.
echo   ERROR: Python was not found.
echo   Install Python 3.11 or newer and make sure it is on PATH.
exit /b 1

:find_packager
set "PACKAGER="
if defined PROJECT_PACKAGER if exist "%PROJECT_PACKAGER%" set "PACKAGER=%PROJECT_PACKAGER%"
if defined PACKAGER exit /b 0
if exist "%~dp0project_packager.py" set "PACKAGER=%~dp0project_packager.py"
if defined PACKAGER exit /b 0
if exist "%CD%\project_packager.py" set "PACKAGER=%CD%\project_packager.py"
if defined PACKAGER exit /b 0
if exist "%CD%\..\project_packager.py" set "PACKAGER=%CD%\..\project_packager.py"
if defined PACKAGER exit /b 0
for %%F in (project_packager.py) do if not "%%~$PATH:F"=="" set "PACKAGER=%%~$PATH:F"
if defined PACKAGER exit /b 0
echo.
echo   ERROR: project_packager.py was not found.
echo.
echo   Looked in:
echo     - the PROJECT_PACKAGER environment variable
echo     - this folder:   %~dp0
echo     - the project:   %CD%
echo     - its parent
echo     - PATH
echo.
echo   Either copy project_packager.py next to this menu, or set a permanent
echo   pointer to a shared copy:
echo.
echo     setx PROJECT_PACKAGER "C:\Tools\project_packager.py"
echo.
exit /b 1

:fatal
echo.
pause
endlocal
exit /b 1
