# Halt Core - PyPI Publishing & Packaging Script
# This script automates building, validating, and uploading the halt-core package to PyPI.

$ErrorActionPreference = "Stop"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "                    HALT CORE PyPI DEPLOYMENT UTILITY                   " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. Check Virtual Environment
$venvPython = Join-Path (Get-Location) "venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    Write-Host "[INFO] Detected local virtual environment." -ForegroundColor Green
    $pythonCmd = $venvPython
} else {
    Write-Host "[WARNING] Local virtual environment not found at .\venv. Using system Python instead." -ForegroundColor Yellow
    $pythonCmd = "python"
}

# Verify Python works
try {
    $pythonVersion = & $pythonCmd --version
    Write-Host "[INFO] Using Python: $pythonVersion" -ForegroundColor Gray
} catch {
    Write-Error "Python is not installed or not available in the PATH."
}

# 2. Clean old builds
Write-Host "`n[1/4] Cleaning previous build artifacts..." -ForegroundColor Blue
$cleanPaths = @("dist", "build", "halt_core.egg-info")
foreach ($path in $cleanPaths) {
    if (Test-Path $path) {
        Write-Host "  Removing $path..." -ForegroundColor Gray
        Remove-Item -Path $path -Recurse -Force
    }
}
Write-Host "  Clean complete." -ForegroundColor Green

# 3. Ensure packaging tools are installed/updated
Write-Host "`n[2/4] Ensuring build & twine are installed and up-to-date..." -ForegroundColor Blue
try {
    & $pythonCmd -m pip install --upgrade pip build twine
    Write-Host "  Packaging tools successfully installed/updated." -ForegroundColor Green
} catch {
    Write-Error "Failed to install packaging tools. Make sure your internet connection is active."
}

# 4. Build package (Source Distribution and Wheel)
Write-Host "`n[3/4] Building source distribution and wheel files..." -ForegroundColor Blue
try {
    & $pythonCmd -m build
    Write-Host "  Build completed successfully. Check the 'dist/' folder." -ForegroundColor Green
} catch {
    Write-Error "Package build process failed. Check your pyproject.toml configuration."
}

# 5. Validate package metadata
Write-Host "`n[4/4] Validating build artifacts with twine check..." -ForegroundColor Blue
try {
    # Check both dist/* files
    & $pythonCmd -m twine check dist/*
    Write-Host "  Package description and metadata are valid for PyPI!" -ForegroundColor Green
} catch {
    Write-Warning "Twine check failed or found warnings. Make sure your README.md is properly formatted as markdown."
}

# 6. Deployment Menu
Write-Host "`n========================================================================" -ForegroundColor Cyan
Write-Host "Build complete! Please choose a deployment target:" -ForegroundColor Cyan
Write-Host "1) Upload to TestPyPI (Recommended first to verify details)"
Write-Host "2) Upload to Official PyPI"
Write-Host "3) Exit"
Write-Host "========================================================================" -ForegroundColor Cyan

$choice = Read-Host "Select option (1-3)"

switch ($choice) {
    "1" {
        Write-Host "`n[DEPLOYING] Preparing TestPyPI Upload..." -ForegroundColor Yellow
        Write-Host "Note: When prompted, use '__token__' for the username and your TestPyPI API token (pypi-...) for the password." -ForegroundColor Gray
        & $pythonCmd -m twine upload --repository testpypi dist/*
    }
    "2" {
        Write-Host "`n[DEPLOYING] Preparing Official PyPI Upload..." -ForegroundColor Red
        Write-Host "Note: When prompted, use '__token__' for the username and your PyPI API token (pypi-...) for the password." -ForegroundColor Gray
        & $pythonCmd -m twine upload dist/*
    }
    "3" {
        Write-Host "`nExited without uploading." -ForegroundColor Green
    }
    Default {
        Write-Host "`nInvalid selection. Exiting." -ForegroundColor Yellow
    }
}
