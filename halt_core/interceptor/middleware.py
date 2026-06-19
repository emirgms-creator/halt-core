import logging
import time
from halt_core.interceptor.engine import RuleEngine
from halt_core.interceptor.memory import MemoryManager
from halt_core.models.schemas import AgentAction, SecurityDecision

# Configure module-level logging
logger = logging.getLogger("halt_core.interceptor")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

class CommandInterceptor:
    """
    Acts as the security broker (middleware) that intercepts incoming Agent actions.
    It logs the event, coordinates with the RuleEngine to evaluate safety,
    audits the result, and returns the final SecurityDecision.
    """

    def __init__(self, rule_engine: RuleEngine, memory_manager: MemoryManager):
        self.rule_engine = rule_engine
        self.memory_manager = memory_manager

    def intercept(self, action: AgentAction) -> SecurityDecision:
        """
        Intercepts and evaluates an action against rules, passing session memory.
        
        Args:
            action (AgentAction): The command package.
            
        Returns:
            SecurityDecision: The approved or rejected security decision.
        """
        logger.info(
            f"INTERCEPTED: Agent={action.agent_id} | "
            f"Type={action.action_type.value} | "
            f"Command='{action.command}'"
        )
        
        # Retrieve context history for this specific agent
        history = self.memory_manager.get_history(action.agent_id)
        
        # Measure rule evaluation latency including state lookups
        start_time = time.perf_counter()
        decision = self.rule_engine.evaluate(action, history)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        
        # Assign latency measurement to decision schema
        decision.latency_ms = latency_ms
        
        if decision.approved:
            # Commit the approved action to the agent's session memory context
            self.memory_manager.add_action(action.agent_id, action)
            logger.info(
                f"APPROVED (Latency: {latency_ms:.4f}ms): Rule={decision.rule_triggered} | Reason={decision.reason}"
            )
        else:
            logger.warning(
                f"REJECTED (Latency: {latency_ms:.4f}ms): Rule={decision.rule_triggered} | Reason={decision.reason}"
            )
            if decision.remediation:
                logger.info(f"REMEDIATION SUGGESTION: {decision.remediation}")
                
        return decision
