import re
from typing import List
from halt_core.interceptor.rules.base import BaseRule
from halt_core.models.schemas import AgentAction, SecurityDecision, ActionType

class SuspiciousSequenceRule(BaseRule):
    """
    A stateful security policy check.
    Prevents execution or execution preparation (e.g., chmod +x) of assets
    downloaded in the same session to block multi-step Remote Code Execution (RCE) chains.
    """

    def __init__(self):
        # Match chmod +x or numeric execute permissions (e.g., 755)
        self._exec_prep_patterns = [
            re.compile(r"\bchmod\s+.*?\+x", re.IGNORECASE),
            re.compile(r"\bchmod\s+.*?7[5-7][5-7]", re.IGNORECASE),
        ]
        # Match starting scripts locally (./script.sh, bash script.sh)
        self._exec_run_patterns = [
            re.compile(r"(^|\s|\||&|;)\s*\./", re.IGNORECASE),
            re.compile(r"\b(bash|sh|zsh|python|python3)\s+.*?\.sh", re.IGNORECASE),
        ]
        
        # Download utilities to look for in past commands
        self._download_keywords = ["curl", "wget"]

    @property
    def name(self) -> str:
        return "SuspiciousSequenceRule"

    def evaluate(self, action: AgentAction, history: List[AgentAction]) -> SecurityDecision:
        # Sequence tracking is applicable only for terminal shell environments
        if action.action_type != ActionType.SHELL:
            return SecurityDecision(
                approved=True,
                reason="Action is not Shell. Rule skipped.",
                rule_triggered=self.name
            )

        command = action.command
        
        # Check if current action is execution prep or execution run
        is_prep = any(p.search(command) for p in self._exec_prep_patterns)
        is_run = any(p.search(command) for p in self._exec_run_patterns)

        if is_prep or is_run:
            # Inspect agent's history context to see if they ran download commands
            downloads = []
            for past_action in history:
                if past_action.action_type == ActionType.SHELL:
                    past_cmd = past_action.command.lower()
                    for kw in self._download_keywords:
                        # Use boundary matching to verify the utility name
                        if re.search(rf"\b{kw}\b", past_cmd):
                            downloads.append(past_action.command)
                            break
            
            if downloads:
                downloads_str = "; ".join([f"'{cmd}'" for cmd in downloads])
                action_desc = "change execution permissions (chmod)" if is_prep else "execute a local script"
                return SecurityDecision(
                    approved=False,
                    reason=(
                        f"Stateful security violation: Agent attempted to {action_desc} via '{command}' "
                        f"after downloading external files earlier in this session via: {downloads_str}."
                    ),
                    remediation=(
                        "Executing or authorizing files downloaded over the network in the same session is prohibited "
                        "to mitigate Remote Code Execution (RCE) attacks. Please inspect the script content "
                        "using safe read-only operations (e.g., 'cat <filename>') instead of executing it directly. "
                        "Please try again safely."
                    ),
                    rule_triggered=self.name
                )

        return SecurityDecision(
            approved=True,
            reason="No suspicious multi-step sequences detected.",
            rule_triggered=self.name
        )
