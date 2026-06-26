# PyPI Packaging and Deployment Guide: `halt-core`

This guide explains how to package the **Halt Core** (`halt-core`) library, verify the distribution artifacts, and securely publish it to the official Python Package Index (PyPI).

---

## 🔒 Security Best Practices

1. **Use API Tokens (Never Passwords)**: PyPI requires or strongly recommends API tokens. When prompted for credentials:
   - **Username**: Use the literal string `__token__`.
   - **Password**: Use your PyPI API token value (starts with `pypi-`).
2. **Clean Before Rebuilding**: Stale files in the `dist/` folder will be uploaded along with your new version if you do not clean them. Always delete `dist/`, `build/`, and `*.egg-info` folders before building.
3. **Verify Build Contents**: Ensure only your library code (`halt_core/`) and package config files are packaged. Exclude local virtual environments (`venv/`), secrets, and test configs.
4. **Test on TestPyPI**: Always upload to the TestPyPI server first to verify metadata formatting, links, and that installation runs smoothly without breaking production pipelines.

---

## 🛠️ Step-by-Step Instructions

### Step 1: Install & Upgrade Packaging Tools
Before building, ensure you have the latest versions of `pip`, `build`, and `twine` installed in your virtual environment:

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Upgrade build tools
python -m pip install --upgrade pip build twine
```

---

### Step 2: Generate Distribution Files Safely
Run the `build` module. It automatically compiles your code into two standard formats:
1. **Source Distribution (`sdist`)**: A `.tar.gz` archive containing the source code.
2. **Built Distribution (`wheel`)**: A `.whl` binary package ready for fast pip installation.

```powershell
# Build the package
python -m build
```

> [!NOTE]  
> After building, verify that `dist/` contains exactly two files:
> - `halt_core-0.1.0.tar.gz`
> - `halt_core-0.1.0-py3-none-any.whl`

---

### Step 3: Validate the Distributions
Verify that your metadata formats, README rendering, and requirements configuration comply with PyPI standards using `twine check`:

```powershell
python -m twine check dist/*
```

If the checks pass, you'll see:
`Checking dist/halt_core-0.1.0-py3-none-any.whl: Passed`
`Checking dist/halt_core-0.1.0.tar.gz: Passed`

---

### Step 4: Publish to TestPyPI (Validation Run)
TestPyPI is a separate package registry instance for testing. Upload your package to verify formatting and installability:

```powershell
python -m twine upload --repository testpypi dist/*
```

* **Username**: `__token__`
* **Password**: *[Your TestPyPI API Token]*

#### Test Installation
You can verify the package installs correctly from TestPyPI using a temporary virtual environment:
```powershell
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ halt-core
```
*(The `--extra-index-url` ensures dependencies like `fastapi` and `pydantic` are pulled from official PyPI).*

---

### Step 5: Publish to Official PyPI
Once verification on TestPyPI is successful, deploy the build to production:

```powershell
python -m twine upload dist/*
```

* **Username**: `__token__`
* **Password**: *[Your Production PyPI API Token]*

Once uploaded, developers worldwide can run:
```powershell
pip install halt-core
```

---

## ⚡ Automated Deployment Script

An automated publishing script has been provided at [publish.ps1](file:///c:/Users/Bekir/Desktop/AI%20OS/publish.ps1). You can run this directly in PowerShell to clean, upgrade, build, check, and trigger the upload flow interactively:

```powershell
.\publish.ps1
```
