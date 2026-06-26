import logging
import time
import json
from halt_core.interceptor.engine import RuleEngine
from halt_core.interceptor.memory import MemoryManager
from halt_core.models.schemas import AgentAction, SecurityDecision

class StructuredJSONFormatter(logging.Formatter):
    """
    Formatter that converts LogRecords into structured JSON strings.
    Extracts custom extra properties dynamically.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage()
        }
        
        # Copy custom properties from record.__dict__ (passed via extra=...)
        standard_attrs = {
            "args", "asctime", "created", "exc_info", "exc_text", "filename", 
            "funcName", "levelname", "levelno", "lineno", "module", "msecs", 
            "msg", "name", "pathname", "process", "processName", "relativeCreated", 
            "stack_info", "thread", "threadName"
        }
        for key, val in record.__dict__.items():
            if key not in standard_attrs:
                log_data[key] = val
        return json.dumps(log_data)

# Configure module-level logging for structured JSON format
logger = logging.getLogger("halt_core.interceptor")
logger.setLevel(logging.INFO)

# Configure structured formatter if no handlers exist
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJSONFormatter())
    logger.addHandler(handler)
    logger.propagate = False  # Avoid double logging to parent root log handlers

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
        Logs the audit details in structured JSON format.
        
        Args:
            action (AgentAction): The command package.
            
        Returns:
            SecurityDecision: The approved or rejected security decision.
        """
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

        # Telemetry extra fields for structured log
        log_extra = {
            "agent_id": action.agent_id,
            "action_type": action.action_type.value,
            "command": action.command,
            "approved": decision.approved,
            "rule_triggered": decision.rule_triggered,
            "reason": decision.reason,
            "remediation": decision.remediation,
            "latency_ms": latency_ms
        }

        if decision.approved:
            logger.info("Agent action evaluated and approved.", extra=log_extra)
        else:
            logger.warning("Agent action evaluated and rejected.", extra=log_extra)
                
        return decision
