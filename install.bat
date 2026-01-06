@echo off
REM FIPS 140-3 Toolkit - Windows Installation Script
REM This script checks for and installs all required dependencies
REM
REM Usage: Double-click install.bat
REM    or: Run from Command Prompt: install.bat
REM

setlocal EnableDelayedExpansion

echo.
echo ===========================================
echo   FIPS 140-3 Toolkit - Dependency Installer
echo ===========================================
echo.

REM Check for Python
echo [*] Checking for Python 3...

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    where python3 >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        goto :no_python
    ) else (
        set PYTHON_CMD=python3
    )
) else (
    set PYTHON_CMD=python
)

REM Verify it's Python 3
for /f "tokens=2" %%i in ('%PYTHON_CMD% --version 2^>^&1') do set PYTHON_VERSION=%%i
echo %PYTHON_VERSION% | findstr /r "^3\." >nul
if %ERRORLEVEL% NEQ 0 (
    goto :no_python
)

REM Extract major.minor version
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set PYTHON_MAJOR=%%a
    set PYTHON_MINOR=%%b
)

REM Check version is 3.8+
if %PYTHON_MAJOR% LSS 3 goto :old_python
if %PYTHON_MAJOR% EQU 3 if %PYTHON_MINOR% LSS 8 goto :old_python

echo [+] Found Python %PYTHON_VERSION%

REM Check for pip
echo [*] Checking for pip...

%PYTHON_CMD% -m pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] pip is not installed. Attempting to install...

    REM Try ensurepip first
    %PYTHON_CMD% -m ensurepip --upgrade >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        echo [+] pip installed via ensurepip
        goto :pip_installed
    )

    REM Download get-pip.py
    echo [*] Downloading pip installer...

    REM Try PowerShell to download
    powershell -Command "& {Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%TEMP%\get-pip.py'}" >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        REM Try curl if available
        curl -sS https://bootstrap.pypa.io/get-pip.py -o "%TEMP%\get-pip.py" >nul 2>&1
        if %ERRORLEVEL% NEQ 0 (
            echo [X] Failed to download pip installer.
            echo.
            echo Please manually install pip:
            echo   1. Download: https://bootstrap.pypa.io/get-pip.py
            echo   2. Run: python get-pip.py
            echo.
            goto :error_exit
        )
    )

    echo [*] Installing pip...
    %PYTHON_CMD% "%TEMP%\get-pip.py" --user
    del "%TEMP%\get-pip.py" >nul 2>&1

    %PYTHON_CMD% -m pip --version >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [X] pip installation failed
        goto :error_exit
    )
    echo [+] pip installed successfully
)

:pip_installed
for /f "tokens=2" %%i in ('%PYTHON_CMD% -m pip --version') do set PIP_VERSION=%%i
echo [+] Found pip %PIP_VERSION%

REM Upgrade pip
echo [*] Upgrading pip to latest version...
%PYTHON_CMD% -m pip install --upgrade pip --quiet 2>nul

REM Check if requests is installed
echo [*] Checking for required dependencies...

%PYTHON_CMD% -c "import requests" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    for /f %%i in ('%PYTHON_CMD% -c "import requests; print(requests.__version__)"') do set REQ_VERSION=%%i
    echo [+] requests !REQ_VERSION! already installed
) else (
    echo [*] Installing requests...
    %PYTHON_CMD% -m pip install requests --quiet
    if %ERRORLEVEL% NEQ 0 (
        echo [X] Failed to install requests
        goto :error_exit
    )
    for /f %%i in ('%PYTHON_CMD% -c "import requests; print(requests.__version__)"') do set REQ_VERSION=%%i
    echo [+] requests !REQ_VERSION! installed
)

REM Verify installation
echo.
echo [*] Verifying installation...

%PYTHON_CMD% -c "import requests" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [X] Installation verification failed
    goto :error_exit
)

echo [+] All dependencies installed successfully!
echo.

REM Check if we're in the toolkit directory
if exist "fips-toolkit.py" (
    echo [+] Ready to run the toolkit!
    echo.
    echo Run the toolkit with:
    echo   %PYTHON_CMD% fips-toolkit.py
    echo.

    set /p RUNNOW="Would you like to run the toolkit now? [Y/n] "
    if /i "!RUNNOW!"=="" set RUNNOW=Y
    if /i "!RUNNOW!"=="Y" (
        %PYTHON_CMD% fips-toolkit.py
    )
) else (
    echo [+] Dependencies installed!
    echo.
    echo Navigate to the toolkit directory and run:
    echo   %PYTHON_CMD% fips-toolkit.py
)

goto :end

:no_python
echo [X] Python 3 is not installed!
echo.
echo To install Python 3 on Windows:
echo.
echo   1. Download from: https://www.python.org/downloads/windows/
echo.
echo   2. Run the installer and IMPORTANT:
echo      [X] Check "Add Python to PATH" at the bottom of the installer!
echo.
echo   3. After installation, close and reopen Command Prompt
echo.
echo   4. Run this script again: install.bat
echo.
echo Direct download links:
echo   Python 3.12: https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe
echo   Python 3.11: https://www.python.org/ftp/python/3.11.11/python-3.11.11-amd64.exe
echo.
goto :error_exit

:old_python
echo [X] Python 3.8 or higher is required (found %PYTHON_VERSION%)
echo.
echo Please upgrade Python: https://www.python.org/downloads/windows/
echo.
goto :error_exit

:error_exit
echo.
echo Installation failed. Please resolve the issues above and try again.
pause
exit /b 1

:end
echo.
pause
