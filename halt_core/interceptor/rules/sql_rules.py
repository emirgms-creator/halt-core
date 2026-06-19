import re
from typing import List
from halt_core.interceptor.rules.base import BaseRule
from halt_core.models.schemas import AgentAction, SecurityDecision, ActionType

class SQLDenyListRule(BaseRule):
    """
    Checks SQL actions against a deny-list of dangerous/destructive operations.
    Blocks DROP, DELETE, TRUNCATE, and ALTER commands using regex boundary checks
    to avoid false positives on substrings (e.g. matching 'delete' but not 'deleted_at').
    """

    def __init__(self):
        self._deny_list = ["DROP", "DELETE", "TRUNCATE", "ALTER"]
        # Compile patterns using word boundaries to ensure accurate matching
        self._patterns = {
            kw: re.compile(rf"\b{kw}\b", re.IGNORECASE) for kw in self._deny_list
        }

    @property
    def name(self) -> str:
        return "SQLDenyListRule"

    def evaluate(self, action: AgentAction, history: List[AgentAction]) -> SecurityDecision:
        # Check if the action is of SQL type
        if action.action_type != ActionType.SQL:
            return SecurityDecision(
                approved=True,
                reason="Action is not SQL. Rule skipped.",
                rule_triggered=self.name
            )

        command = action.command
        violated_keywords = []

        for kw, pattern in self._patterns.items():
            if pattern.search(command):
                violated_keywords.append(kw)

        if violated_keywords:
            violated_str = ", ".join(violated_keywords)
            return SecurityDecision(
                approved=False,
                reason=f"Action rejected because SQL command contains blocked destructive keyword(s): {violated_str}.",
                remediation=(
                    "Do not execute destructive operations. "
                    "If you need to query data, use 'SELECT'. If you need to clean up data, "
                    "please consult the system administrator or use soft-deletion columns instead of DELETE/DROP. "
                    "Please try again safely."
                ),
                rule_triggered=self.name
            )

        return SecurityDecision(
            approved=True,
            reason="No blocked SQL keywords detected.",
            rule_triggered=self.name
        )
