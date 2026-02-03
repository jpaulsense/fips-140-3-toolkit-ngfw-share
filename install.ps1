#Requires -Version 5.1
<#
.SYNOPSIS
    FIPS 140-3 Toolkit - Windows PowerShell Installation Script

.DESCRIPTION
    This script checks for and installs all required dependencies for the FIPS 140-3 Toolkit.
    - Verifies Python 3.8+ is installed
    - Installs pip if missing
    - Installs the 'requests' Python package
    - Offers to run the toolkit after installation

.EXAMPLE
    .\install.ps1

.NOTES
    Run this script from the toolkit directory.
    You may need to run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#>

$ErrorActionPreference = "Stop"

# Output functions
function Write-Status {
    param([string]$Message)
    Write-Host "[*] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Error {
    param([string]$Message)
    Write-Host "[X] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

Write-Host ""
Write-Host "==========================================="
Write-Host "  FIPS 140-3 Toolkit - Dependency Installer"
Write-Host "==========================================="
Write-Host ""

Write-Status "Detected: Windows PowerShell"

# Check for Python
Write-Status "Checking for Python 3..."

$PythonCmd = $null
$PythonVersion = $null

# Try python first, then python3
foreach ($cmd in @("python", "python3")) {
    try {
        $versionOutput = & $cmd --version 2>&1
        if ($versionOutput -match "Python (\d+\.\d+\.\d+)") {
            $version = $Matches[1]
            if ($version -match "^3\.") {
                $PythonCmd = $cmd
                $PythonVersion = $version
                break
            }
        }
    }
    catch {
        # Command not found, continue
    }
}

if (-not $PythonCmd) {
    Write-Error "Python 3 is not installed!"
    Write-Host ""
    Write-Host "To install Python 3 on Windows:"
    Write-Host ""
    Write-Host "  1. Download from: https://www.python.org/downloads/windows/"
    Write-Host ""
    Write-Host "  2. Run the installer and IMPORTANT:"
    Write-Host "     [X] Check 'Add Python to PATH' at the bottom of the installer!"
    Write-Host ""
    Write-Host "  3. After installation, close and reopen PowerShell"
    Write-Host ""
    Write-Host "  4. Run this script again: .\install.ps1"
    Write-Host ""
    Write-Host "Direct download links:"
    Write-Host "  Python 3.12: https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe"
    Write-Host "  Python 3.11: https://www.python.org/ftp/python/3.11.11/python-3.11.11-amd64.exe"
    Write-Host ""
    exit 1
}

# Check Python version is 3.8+
$versionParts = $PythonVersion -split "\."
$major = [int]$versionParts[0]
$minor = [int]$versionParts[1]

if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 8)) {
    Write-Error "Python 3.8 or higher is required (found $PythonVersion)"
    Write-Host ""
    Write-Host "Please upgrade Python: https://www.python.org/downloads/windows/"
    Write-Host ""
    exit 1
}

Write-Success "Found Python $PythonVersion"

# Check for pip
Write-Status "Checking for pip..."

$pipWorks = $false
try {
    $null = & $PythonCmd -m pip --version 2>&1
    $pipWorks = $true
}
catch {
    $pipWorks = $false
}

if (-not $pipWorks) {
    Write-Warning "pip is not installed. Attempting to install..."

    # Try ensurepip first
    try {
        & $PythonCmd -m ensurepip --upgrade 2>&1 | Out-Null
        Write-Success "pip installed via ensurepip"
        $pipWorks = $true
    }
    catch {
        # Download and run get-pip.py
        Write-Status "Downloading pip installer..."
        $getPipPath = Join-Path $env:TEMP "get-pip.py"

        try {
            Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $getPipPath -UseBasicParsing
        }
        catch {
            Write-Error "Failed to download pip installer."
            Write-Host ""
            Write-Host "Please manually install pip:"
            Write-Host "  1. Download: https://bootstrap.pypa.io/get-pip.py"
            Write-Host "  2. Run: $PythonCmd get-pip.py"
            Write-Host ""
            exit 1
        }

        Write-Status "Installing pip..."
        & $PythonCmd $getPipPath --user
        Remove-Item $getPipPath -Force -ErrorAction SilentlyContinue

        # Verify pip installed
        try {
            $null = & $PythonCmd -m pip --version 2>&1
            $pipWorks = $true
            Write-Success "pip installed successfully"
        }
        catch {
            Write-Error "pip installation failed"
            exit 1
        }
    }
}

if ($pipWorks) {
    $pipVersion = (& $PythonCmd -m pip --version) -replace "pip (\S+).*", '$1'
    Write-Success "Found pip $pipVersion"
}

# Determine script directory and venv path
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $ScriptDir ".venv"
$UseVenv = $false

# Check if a venv already exists with requests
$venvPython = Join-Path $VenvDir "Scripts\python.exe"
if (Test-Path $venvPython) {
    $null = & $venvPython -c "import requests" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $PythonCmd = $venvPython
        $UseVenv = $true
        $requestsVersion = & $PythonCmd -c "import requests; print(requests.__version__)"
        Write-Success "Using existing virtual environment"
        Write-Success "requests $requestsVersion already installed (venv)"
        $requestsInstalled = $true
    }
}

if (-not $UseVenv) {
    # Check if requests already available system-wide
    $requestsInstalled = $false
    try {
        $requestsVersion = & $PythonCmd -c "import requests; print(requests.__version__)" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $requestsInstalled = $true
            Write-Success "requests $requestsVersion already installed"
        }
    }
    catch {
        $requestsInstalled = $false
    }
}

if (-not $requestsInstalled) {
    # Upgrade pip
    Write-Status "Upgrading pip to latest version..."
    & $PythonCmd -m pip install --upgrade pip --quiet 2>&1 | Out-Null

    # Try normal install
    Write-Status "Installing requests..."
    & $PythonCmd -m pip install requests --quiet 2>&1 | Out-Null

    $null = & $PythonCmd -c "import requests" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $requestsVersion = & $PythonCmd -c "import requests; print(requests.__version__)"
        Write-Success "requests $requestsVersion installed"
        $requestsInstalled = $true
    }

    # Try --user install
    if (-not $requestsInstalled) {
        Write-Warning "System install failed, trying user install..."
        & $PythonCmd -m pip install requests --user --quiet 2>&1 | Out-Null

        $null = & $PythonCmd -c "import requests" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $requestsVersion = & $PythonCmd -c "import requests; print(requests.__version__)"
            Write-Success "requests $requestsVersion installed (user)"
            $requestsInstalled = $true
        }
    }

    # Fall back to virtual environment (PEP 668 / externally managed)
    if (-not $requestsInstalled) {
        Write-Warning "pip install blocked (PEP 668 - externally managed environment)"
        Write-Status "Creating virtual environment at .venv ..."

        & $PythonCmd -m venv $VenvDir 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to create virtual environment"
            Write-Host ""
            Write-Host "Please install Python from https://www.python.org/downloads/windows/"
            Write-Host "(The official installer does not have this restriction)"
            exit 1
        }

        Write-Success "Virtual environment created"
        $UseVenv = $true
        $PythonCmd = Join-Path $VenvDir "Scripts\python.exe"

        Write-Status "Installing requests in virtual environment..."
        & $PythonCmd -m pip install --upgrade pip --quiet 2>&1 | Out-Null
        & $PythonCmd -m pip install requests --quiet 2>&1 | Out-Null

        $null = & $PythonCmd -c "import requests" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install requests in virtual environment"
            exit 1
        }

        $requestsVersion = & $PythonCmd -c "import requests; print(requests.__version__)"
        Write-Success "requests $requestsVersion installed (venv)"
        $requestsInstalled = $true
    }
}

# Verify installation
Write-Host ""
Write-Status "Verifying installation..."

$null = & $PythonCmd -c "import requests" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Installation verification failed"
    exit 1
}
Write-Success "All dependencies installed successfully!"

# Check if we're in the toolkit directory
Write-Host ""
if (Test-Path "fips-toolkit.py") {
    Write-Success "Ready to run the toolkit!"
    Write-Host ""

    if ($UseVenv) {
        Write-Host "A virtual environment was created. Run the toolkit with:"
        Write-Host ""
        Write-Host "  Option 1 - Use the venv Python directly (recommended):"
        Write-Host "    $PythonCmd fips-toolkit.py"
        Write-Host ""
        Write-Host "  Option 2 - Activate the venv first:"
        Write-Host "    .venv\Scripts\Activate.ps1"
        Write-Host "    python fips-toolkit.py"
        Write-Host ""
    }
    else {
        Write-Host "Run the toolkit with:"
        Write-Host "  $PythonCmd fips-toolkit.py"
        Write-Host ""
    }

    $runNow = Read-Host "Would you like to run the toolkit now? [Y/n]"
    if ($runNow -eq "" -or $runNow -match "^[Yy]") {
        & $PythonCmd fips-toolkit.py
    }
}
else {
    Write-Success "Dependencies installed!"
    Write-Host ""
    if ($UseVenv) {
        Write-Host "A virtual environment was created at: $VenvDir"
        Write-Host ""
        Write-Host "Navigate to the toolkit directory and run:"
        Write-Host "  $PythonCmd fips-toolkit.py"
    }
    else {
        Write-Host "Navigate to the toolkit directory and run:"
        Write-Host "  $PythonCmd fips-toolkit.py"
    }
}

Write-Host ""
