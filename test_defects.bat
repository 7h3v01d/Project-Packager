@echo off
REM Outstanding work, shown as XFAIL. Tests are marked xfail(strict=True), so
REM this command SUCCEEDS while listing them. As of v3.1.0 there are none,
REM and pytest reports "no tests ran" (exit 5), which is the good outcome.
python -m pytest -m defect -rx
if errorlevel 6 goto :unexpected
if errorlevel 5 (
    echo.
    echo OK - no outstanding defect tests.
    goto :done
)
if errorlevel 1 goto :unexpected
echo.
echo OK - outstanding work listed above as XFAIL.
goto :done
:unexpected
echo.
echo UNEXPECTED: a defect test passed, or the run failed. Check markers.
:done
pause
