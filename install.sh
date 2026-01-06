#!/bin/bash
#
# FIPS 140-3 Toolkit - macOS/Linux Installation Script
# This script checks for and installs all required dependencies
#
# Usage: ./install.sh
#    or: bash install.sh
#    or: curl -fsSL <raw-url> | bash
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

echo ""
echo "==========================================="
echo "  FIPS 140-3 Toolkit - Dependency Installer"
echo "==========================================="
echo ""

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    print_status "Detected: macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    print_status "Detected: Linux"
else
    print_warning "Detected: $OSTYPE (will attempt Linux-style installation)"
    OS="linux"
fi

# Check for Python 3
print_status "Checking for Python 3..."

PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    # Check if 'python' is Python 3
    if python --version 2>&1 | grep -q "Python 3"; then
        PYTHON_CMD="python"
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    print_error "Python 3 is not installed!"
    echo ""
    if [ "$OS" == "macos" ]; then
        echo "To install Python 3 on macOS:"
        echo ""
        echo "  Option 1 - Official installer (recommended):"
        echo "    Download from: https://www.python.org/downloads/macos/"
        echo ""
        echo "  Option 2 - Using Homebrew:"
        echo "    brew install python3"
        echo ""
    else
        echo "To install Python 3 on Linux:"
        echo ""
        echo "  Ubuntu/Debian:"
        echo "    sudo apt update && sudo apt install python3 python3-pip"
        echo ""
        echo "  RHEL/CentOS/Fedora:"
        echo "    sudo dnf install python3 python3-pip"
        echo "    # or: sudo yum install python3 python3-pip"
        echo ""
        echo "  Arch Linux:"
        echo "    sudo pacman -S python python-pip"
        echo ""
    fi
    exit 1
fi

# Get Python version
PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

print_success "Found Python $PYTHON_VERSION"

# Check Python version is 3.8+
if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    print_error "Python 3.8 or higher is required (found $PYTHON_VERSION)"
    echo ""
    echo "Please upgrade Python: https://www.python.org/downloads/"
    exit 1
fi

# Check for pip
print_status "Checking for pip..."

PIP_CMD=""
if $PYTHON_CMD -m pip --version &> /dev/null; then
    PIP_CMD="$PYTHON_CMD -m pip"
elif command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
fi

if [ -z "$PIP_CMD" ]; then
    print_warning "pip is not installed. Attempting to install..."

    # Try to install pip using ensurepip
    if $PYTHON_CMD -m ensurepip --upgrade &> /dev/null; then
        print_success "pip installed via ensurepip"
        PIP_CMD="$PYTHON_CMD -m pip"
    else
        # Download and run get-pip.py
        print_status "Downloading get-pip.py..."
        if command -v curl &> /dev/null; then
            curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
        elif command -v wget &> /dev/null; then
            wget -q https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py
        else
            print_error "Neither curl nor wget found. Cannot download pip installer."
            echo ""
            echo "Please install curl or wget, or manually install pip:"
            echo "  https://pip.pypa.io/en/stable/installation/"
            exit 1
        fi

        print_status "Installing pip..."
        $PYTHON_CMD /tmp/get-pip.py --user
        rm -f /tmp/get-pip.py
        PIP_CMD="$PYTHON_CMD -m pip"
        print_success "pip installed successfully"
    fi
else
    PIP_VERSION=$($PIP_CMD --version 2>&1 | awk '{print $2}')
    print_success "Found pip $PIP_VERSION"
fi

# Upgrade pip to latest version
print_status "Upgrading pip to latest version..."
$PIP_CMD install --upgrade pip --quiet 2>/dev/null || true

# Install requests
print_status "Installing required dependencies..."

if $PYTHON_CMD -c "import requests" &> /dev/null; then
    REQUESTS_VERSION=$($PYTHON_CMD -c "import requests; print(requests.__version__)")
    print_success "requests $REQUESTS_VERSION already installed"
else
    print_status "Installing requests..."
    $PIP_CMD install requests --quiet
    REQUESTS_VERSION=$($PYTHON_CMD -c "import requests; print(requests.__version__)")
    print_success "requests $REQUESTS_VERSION installed"
fi

# Verify installation
echo ""
print_status "Verifying installation..."

if $PYTHON_CMD -c "import requests" &> /dev/null; then
    print_success "All dependencies installed successfully!"
else
    print_error "Installation verification failed"
    exit 1
fi

# Check if we're in the toolkit directory
echo ""
if [ -f "fips-toolkit.py" ]; then
    print_success "Ready to run the toolkit!"
    echo ""
    echo "Run the toolkit with:"
    echo "  $PYTHON_CMD fips-toolkit.py"
    echo ""

    read -p "Would you like to run the toolkit now? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        exec $PYTHON_CMD fips-toolkit.py
    fi
else
    print_success "Dependencies installed!"
    echo ""
    echo "Navigate to the toolkit directory and run:"
    echo "  $PYTHON_CMD fips-toolkit.py"
fi
