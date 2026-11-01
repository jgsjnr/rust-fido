@echo off
setlocal
rem OpenSSH on Windows executes SSH_ASKPASS with GUI/detached console.
rem Forward to Python runner.
set "SCRIPT_DIR=%~dp0"
python "%SCRIPT_DIR%aegis_ssh_askpass.py" %*
