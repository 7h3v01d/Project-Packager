@echo off
REM Outstanding v3.1.0 work, shown as XFAIL. These are marked
REM xfail(strict=True), so this command SUCCEEDS while listing them.
REM A failure here means something was fixed but still carries its marker.
python -m pytest -m defect -rx
if errorlevel 1 (
    echo.
    echo UNEXPECTED: a defect test passed, or the run failed. Check markers.
) else (
    echo.
    echo OK - outstanding work listed above as XFAIL.
)
pause
