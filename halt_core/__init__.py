from halt_core.models.schemas import AgentAction, ActionType
from halt_core.interceptor.memory import MemoryManager
from halt_core.interceptor.rules.sql_rules import SQLDenyListRule
from halt_core.interceptor.rules.shell_rules import ShellDenyListRule
from halt_core.interceptor.rules.stateful_rules import SuspiciousSequenceRule
from halt_core.interceptor.rules.semantic_rules import SemanticIntentRule
from halt_core.interceptor.engine import RuleEngine
from halt_core.interceptor.middleware import CommandInterceptor
from halt_core.ast_guard import is_safe_python_code
from halt_core.shell_parser import is_safe_shell_command
from halt_core.file_guard import is_safe_file_payload

# Shared global interceptor maintaining session memory across SDK calls
_memory_manager = MemoryManager()
_rules = [
    SQLDenyListRule(),
    ShellDenyListRule(),
    SuspiciousSequenceRule(),
    SemanticIntentRule()
]
_engine = RuleEngine(rules=_rules)
_interceptor = CommandInterceptor(rule_engine=_engine, memory_manager=_memory_manager)

def evaluate(action_type: str, command: str, agent_id: str = "default") -> dict:
    """
    High-level entrypoint for the Halt Core library.
    Allows easy validation of agent commands with zero configuration.
    
    Args:
        action_type (str): The system type, either 'sql' or 'shell'.
        command (str): The command or query string to inspect.
        agent_id (str): The requesting agent's session identifier.
        
    Returns:
        dict: The serialized SecurityDecision dictionary containing safety status and reasons.
    """
    # Enforce type check against schemas
    action = AgentAction(
        action_type=ActionType(action_type),
        command=command,
        agent_id=agent_id
    )
    decision = _interceptor.intercept(action)
    return decision.model_dump()
