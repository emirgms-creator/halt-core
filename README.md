<p align="center">
  <img src="logo.svg" alt="Halt Core Logo" width="160" height="160" />
</p>

<h1 align="center">Halt Core</h1>

<p align="center">
  <a href="https://pypi.org/project/halt-core/"><img src="https://img.shields.io/pypi/v/halt-core.svg?color=blue" alt="PyPI Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/emirgms-creator/halt-core.svg?color=green" alt="License"></a>
  <a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code Style"></a>
</p>

<p align="center">
  <strong>Zero-trust security guardrail and sub-millisecond middleware SDK for autonomous AI agents.</strong>
</p>

Halt Core is a zero-trust, sub-millisecond security middleware and execution guardrail for autonomous AI agents. It intercepts, parses, and validates agent-generated system commands and database queries *locally* before they are executed.

---

## Key Capabilities

* **Python AST Shield:** Parses dynamic Python scripts to block unsafe imports (`subprocess`, `sys`), calls (`eval`, `exec`), and dunder sandbox escapes (`__class__`, `__subclasses__`).
* **Deep Shell Parser:** Tokenizes and parses chained terminal commands (separators: `&&`, `||`, `|`, `;`). Unwraps execution wrappers (`sudo`, `env`) and blocks dynamic command execution (e.g. `$(echo rm)`).
* **File Payload Analyzer:** Scans files created by agents (e.g. `.py`, `.sh`, `.bat`) at write-time. Inspects script code and flags obfuscated payload signatures (Fork bombs, Base64 decodes).
* **REST API Service:** Can be run as a standalone language-agnostic HTTP microservice.
* **Structured Logging:** Formats intercept logs as JSON lines for SIEM/telemetry tools.
* **External Configuration:** Customize block lists and settings dynamically using a local `halt_config.json`.

---

## Installation

Ensure you have Python 3.9+ installed.

```bash
pip install halt-core
```

### Optional: Local Semantic Engine (Phi-4-mini)
If the static rules pass but the command is structurally complex, Halt Core can route it to a local Small Language Model (SLM) for intent verification. Install [Ollama](https://ollama.com/) and pull the model:
```bash
ollama run phi4-mini
```

---

## Quick Start

### 1. Python Library Usage
Integrate Halt Core directly into your execution pipelines:

```python
from halt_core import evaluate

# Intercept and validate agent command
decision = evaluate(
    action_type="shell", 
    command="rm -rf /", 
    agent_id="agent_worker_01"
)

if not decision["approved"]:
    print(f"Action blocked: {decision['reason']}")
    print(f"Suggested remediation: {decision['remediation']}")
else:
    # Safe to execute
    pass
```

### 2. Standalone REST API Service
Run the service:
```bash
uvicorn halt_core.main:app --host 0.0.0.0 --port 8000
```
Query the gateway from any programming language (Node.js, Go, Java):
* **Endpoint:** `POST http://localhost:8000/intercept`
* **Payload:** `{"action_type": "shell", "command": "rm -rf /", "agent_id": "agent_01"}`

---

## External Configuration (`halt_config.json`)

To customize security parameters without modifying code, create a `halt_config.json` file in your working directory:

```json
{
  "deny_commands": ["rm", "sudo", "chmod", "wget", "curl"],
  "blocked_modules": ["subprocess", "importlib", "pdb"],
  "blocked_functions": ["eval", "exec"]
}
```

---

## Integration Example: LangChain Secured Tool

To secure LangChain agents, wrap your execution tools with Halt Core. If a command is blocked, the remediation feedback is returned to the agent so it can self-correct:

```python
from langchain.tools import tool
from halt_core import evaluate
import subprocess

@tool
def secured_shell(command: str) -> str:
    """Executes a system shell command, validated by Halt Core."""
    # 1. Intercept command
    decision = evaluate(action_type="shell", command=command, agent_id="agent_01")
    
    # 2. Block if unsafe
    if not decision["approved"]:
        return (
            f"ERROR: Action Blocked by Halt Core Security.\n"
            f"Reason: {decision['reason']}\n"
            f"Remediation: {decision['remediation']}"
        )
        
    # 3. Execute safely if approved
    try:
        res = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        return res.stdout if res.returncode == 0 else res.stderr
    except Exception as e:
        return str(e)
```