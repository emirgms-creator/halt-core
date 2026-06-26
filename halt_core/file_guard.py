import os
import re
from typing import Tuple, Optional
from halt_core.ast_guard import is_safe_python_code
from halt_core.shell_parser import is_safe_shell_command

# Fast scan compiled regex for word boundary matching of risky keywords
RISKY_RE = re.compile(
    r'\b(rm|wget|curl|chmod|sudo|chown|mv|dd|mkfs|eval|exec|system|subprocess|rmtree|base64|b64decode|shutdown|reboot|os|sys|shutil|importlib|socket)\b', 
    re.IGNORECASE
)

# Obfuscated signature patterns
FORK_BOMB_RE = re.compile(r':\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:', re.IGNORECASE)
BASE64_DECODE_RE = re.compile(r'\b(base64\s+-d|base64\s+--decode|certutil\s+-decode)\b', re.IGNORECASE)
HEX_EXEC_RE = re.compile(r'\b(bytes\.fromhex|decode\([\'"]hex[\'"]\))\b', re.IGNORECASE)

EXECUTABLE_EXTENSIONS = {".py", ".sh", ".bat", ".cmd", ".bash", ".zsh", ".ps1"}

def detect_file_type(payload: str, filename: Optional[str] = None) -> str:
    """
    Detects the file type ('python', 'shell', 'batch', 'powershell', or 'text') 
    based on the filename extension and the content shebang.
    """
    if filename:
        ext = os.path.splitext(filename.lower())[1]
        if ext == ".py":
            return "python"
        elif ext in {".sh", ".bash", ".zsh"}:
            return "shell"
        elif ext in {".bat", ".cmd"}:
            return "batch"
        elif ext == ".ps1":
            return "powershell"
            
    # Shebang detection as fallback
    stripped = payload.lstrip()
    if stripped.startswith("#!"):
        first_line = stripped.split('\n', 1)[0]
        if "python" in first_line:
            return "python"
        elif any(shell_name in first_line for shell_name in ["sh", "bash", "zsh", "ksh", "dash"]):
            return "shell"
            
    return "text"

def is_safe_file_payload(payload: str, filename: Optional[str] = None) -> Tuple[bool, str]:
    """
    Fast scans a file payload string to check if it contains obfuscated destructive commands 
    or matches deny-list signatures.
    
    Args:
        payload (str): The file content string.
        filename (str): Optional name of the file being created.
        
    Returns:
        Tuple[bool, str]: (is_safe, reason)
    """
    if not payload.strip():
        return True, "Payload is empty."

    # 1. Signature-based Obfuscation & Fork Bomb Detection (All Files)
    if FORK_BOMB_RE.search(payload):
        return False, "Fork bomb signature detected."
        
    if BASE64_DECODE_RE.search(payload):
        return False, "Obfuscation signature detected: Base64 decoding utility."
        
    if HEX_EXEC_RE.search(payload):
        return False, "Obfuscation signature detected: Hex decoding/execution."

    # 2. Fast Path: If no risky keywords are present, it is safe.
    if not RISKY_RE.search(payload):
        return True, "No dangerous keywords detected."

    # 3. Context-Aware Deep Scanning
    file_type = detect_file_type(payload, filename)

    # If it's a generic text file (e.g. .md, .txt, .json) and doesn't run code directly,
    # we allow it (avoiding false positives on documentation or configs).
    if file_type == "text" and filename:
        ext = os.path.splitext(filename.lower())[1]
        if ext not in EXECUTABLE_EXTENSIONS:
            return True, "Generic non-executable text content containing keywords is allowed."

    if file_type == "python":
        # Route to Python AST Shield
        safe, reason = is_safe_python_code(payload)
        if not safe:
            return False, f"Python payload security violation: {reason}"
            
    elif file_type in {"shell", "powershell", "batch"}:
        # Route line-by-line to Deep Shell Parser
        lines = payload.splitlines()
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped:
                continue
                
            # Filter comments based on script syntax
            if file_type == "batch":
                if line_stripped.lower().startswith("rem") or line_stripped.startswith("::"):
                    continue
            else:  # shell or powershell
                if line_stripped.startswith("#"):
                    continue
                    
            safe, reason = is_safe_shell_command(line_stripped)
            if not safe:
                return False, f"Shell payload security violation on line {line_num}: {reason}"

    return True, "File payload is safe."
