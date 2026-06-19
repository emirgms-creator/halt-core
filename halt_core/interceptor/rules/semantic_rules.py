from typing import List
from halt_core.interceptor.rules.base import BaseRule
from halt_core.interceptor.llm_client import LocalLLMClient
from halt_core.models.schemas import AgentAction, SecurityDecision

class SemanticIntentRule(BaseRule):
    """
    Evaluates the semantic intent of agent commands using a simulated Local LLM.
    Serves as the final compute-intensive security checkpoint to intercept
    obfuscation attacks that bypass literal keyword patterns.
    """

    def __init__(self):
        self._llm_client = LocalLLMClient()

    @property
    def name(self) -> str:
        return "SemanticIntentRule"

    def evaluate(self, action: AgentAction, history: List[AgentAction]) -> SecurityDecision:
        # Submit command text to semantic intent classification
        result = self._llm_client.analyze_intent(action.command)

        if not result.get("safe", True):
            return SecurityDecision(
                approved=False,
                reason=result.get("reason", "Semantic validation flagged the intent of this command as unsafe."),
                remediation=result.get("remediation", "Do not attempt to bypass security policies."),
                rule_triggered=self.name
            )

        return SecurityDecision(
            approved=True,
            reason="Semantic evaluation cleared the command intent.",
            rule_triggered=self.name
        )
