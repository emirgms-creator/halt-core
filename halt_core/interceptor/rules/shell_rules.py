import re
from typing import List
from halt_core.interceptor.rules.base import BaseRule
from halt_core.models.schemas import AgentAction, SecurityDecision, ActionType

class ShellDenyListRule(BaseRule):
    """
    Checks terminal/shell commands against a deny-list of dangerous command utilities
    and dangerous scripting constructs (e.g. fork bombs, curl-to-bash executions).
    """

    def __init__(self):
        self._deny_commands = ["rm", "sudo", "chown", "mkfs", "dd", "shutdown", "reboot", "mv"]
        # Compile patterns using word boundaries to ensure precise matching
        self._command_patterns = {
            cmd: re.compile(rf"\b{cmd}\b", re.IGNORECASE) for cmd in self._deny_commands
        }
        
        # Look for complex dangerous signatures
        self._signature_patterns = {
            "Fork Bomb signature": re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
            "Direct pipeline execution (curl | sh/bash)": re.compile(r"curl\s+.*\s*\|\s*(bash|sh|zsh)", re.IGNORECASE),
            "Direct pipeline execution (wget | sh/bash)": re.compile(r"wget\s+.*\s*\|\s*(bash|sh|zsh)", re.IGNORECASE),
        }

    @property
    def name(self) -> str:
        return "ShellDenyListRule"

    def evaluate(self, action: AgentAction, history: List[AgentAction]) -> SecurityDecision:
        # Check if the action is of shell/terminal type
        if action.action_type != ActionType.SHELL:
            return SecurityDecision(
                approved=True,
                reason="Action is not Shell. Rule skipped.",
                rule_triggered=self.name
            )

        command = action.command
        violated_items = []

        # Check for command keywords
        for cmd, pattern in self._command_patterns.items():
            if pattern.search(command):
                violated_items.append(f"blocked utility '{cmd}'")

        # Check for complex signatures
        for signature_name, pattern in self._signature_patterns.items():
            if pattern.search(command):
                violated_items.append(signature_name)

        if violated_items:
            violated_str = ", ".join(violated_items)
            return SecurityDecision(
                approved=False,
                reason=f"Action rejected because shell command contains: {violated_str}.",
                remediation=(
                    "Running commands with root privileges (sudo), deleting/moving system files (rm, mv), "
                    "modifying permissions (chmod, chown), or pipelining downloads straight to execution "
                    "is blocked. Please use safe commands like 'ls', 'pwd', 'echo', or non-destructive python scripts instead. "
                    "Please try again safely."
                ),
                rule_triggered=self.name
            )

        return SecurityDecision(
            approved=True,
            reason="No blocked Shell commands or signatures detected.",
            rule_triggered=self.name
        )
