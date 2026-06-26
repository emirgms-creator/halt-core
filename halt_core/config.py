import os
import json
from typing import Set

# Default security policy deny-lists
DEFAULT_DENY_COMMANDS = {
    "rm", "wget", "curl", "chmod", "sudo", "chown", "mv", "dd", "mkfs", 
    "shutdown", "reboot", "poweroff", "init", "systemctl", "ufw", "iptables"
}

DEFAULT_BLOCKED_MODULES = {
    "subprocess", "importlib", "sys", "pty", "ctypes", "code", "codeop", 
    "runpy", "commands", "builtins", "pdb", "bdb", "sysconfig", "platform",
    "ctypes.util", "inspect", "trace"
}

DEFAULT_BLOCKED_FUNCTIONS = {
    "eval", "exec", "__import__", "compile", "globals", "locals", "getattr", "setattr"
}

DEFAULT_BLOCKED_CALLS = {
    "system", "popen", "spawn", "rmtree", "Popen", "run", "call", 
    "check_output", "check_call", "getoutput", "getstatusoutput"
}

class ConfigurationManager:
    """
    Central manager for Halt Core's deny-lists.
    Loads settings from 'halt_config.json' in the current working directory if available.
    """
    def __init__(self):
        self.deny_commands: Set[str] = set(DEFAULT_DENY_COMMANDS)
        self.blocked_modules: Set[str] = set(DEFAULT_BLOCKED_MODULES)
        self.blocked_functions: Set[str] = set(DEFAULT_BLOCKED_FUNCTIONS)
        self.blocked_calls: Set[str] = set(DEFAULT_BLOCKED_CALLS)
        self.load_config()

    def load_config(self, filepath: str = "halt_config.json") -> None:
        """
        Reads a JSON configuration file and overrides the default security lists.
        If the file doesn't exist, defaults are used.
        """
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                if "deny_commands" in data:
                    self.deny_commands = {str(cmd) for cmd in data["deny_commands"]}
                if "blocked_modules" in data:
                    self.blocked_modules = {str(mod) for mod in data["blocked_modules"]}
                if "blocked_functions" in data:
                    self.blocked_functions = {str(func) for func in data["blocked_functions"]}
                if "blocked_calls" in data:
                    self.blocked_calls = {str(call) for call in data["blocked_calls"]}
            except Exception as e:
                # Log or print warning silently to avoid disrupting stdout
                import sys
                print(f"[Halt Core Config] Warning: Failed to parse {filepath}: {e}", file=sys.stderr)

    def reset_to_defaults(self) -> None:
        """Resets the configurations back to defaults."""
        self.deny_commands = set(DEFAULT_DENY_COMMANDS)
        self.blocked_modules = set(DEFAULT_BLOCKED_MODULES)
        self.blocked_functions = set(DEFAULT_BLOCKED_FUNCTIONS)
        self.blocked_calls = set(DEFAULT_BLOCKED_CALLS)

# Single global configuration instance accessed by all modules
config = ConfigurationManager()
