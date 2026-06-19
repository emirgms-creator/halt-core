from abc import ABC, abstractmethod
from typing import List
from halt_core.models.schemas import AgentAction, SecurityDecision

class BaseRule(ABC):
    """
    Abstract Base Class for all Halt Core security rules/policies.
    Any concrete policy implementation (regex, AI-based, keyword deny-list)
    must inherit from this class and implement its interface.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        The identifier name of the rule. Used to trace which rule triggered a decision.
        """
        pass

    @abstractmethod
    def evaluate(self, action: AgentAction, history: List[AgentAction]) -> SecurityDecision:
        """
        Evaluates the given action.
        
        Args:
            action (AgentAction): The command or query requested by the agent.
            history (List[AgentAction]): Recent history of approved actions.
            
        Returns:
            SecurityDecision: The approved/denied verdict along with reasons and remediation.
        """
        pass
