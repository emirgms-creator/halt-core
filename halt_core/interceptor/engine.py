from typing import List, Optional
from halt_core.interceptor.rules.base import BaseRule
from halt_core.models.schemas import AgentAction, SecurityDecision

class RuleEngine:
    """
    The main coordinator for rule execution in Halt Core.
    It holds a registry of active rules and evaluates actions against all of them.
    """

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self._rules: List[BaseRule] = rules or []

    def register_rule(self, rule: BaseRule) -> None:
        """
        Registers a new policy rule into the security engine.
        Allows for runtime expansion of security rules (e.g., adding AI-based rules later).
        """
        if rule not in self._rules:
            self._rules.append(rule)

    def evaluate(self, action: AgentAction, history: List[AgentAction]) -> SecurityDecision:
        """
        Evaluates an agent action against all registered security rules.
        Fails fast on the first security policy violation.
        
        Args:
            action (AgentAction): The command or query requested by the agent.
            history (List[AgentAction]): Recent history of approved actions.
            
        Returns:
            SecurityDecision: The aggregated decision.
        """
        for rule in self._rules:
            decision = rule.evaluate(action, history)
            # If any rule rejects the action, return the rejection decision immediately
            if not decision.approved:
                return decision

        # If all rules approve (or skip), approve the action
        return SecurityDecision(
            approved=True,
            reason="Action successfully cleared all security rules.",
            rule_triggered="RuleEngine"
        )
