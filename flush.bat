@echo off
setlocal
for /d /r %%D in (__pycache__) do @if exist "%%D" rd /s /q "%%D"
for /d /r %%D in (.pytest_cache) do @if exist "%%D" rd /s /q "%%D"
for /d /r %%D in (.mypy_cache) do @if exist "%%D" rd /s /q "%%D"
for /d /r %%D in (.ruff_cache) do @if exist "%%D" rd /s /q "%%D"
for /d /r %%D in (*.egg-info) do @if exist "%%D" rd /s /q "%%D"
echo development caches flushed.
endlocal
