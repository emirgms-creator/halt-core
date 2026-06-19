from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

class ActionType(str, Enum):
    SQL = "sql"
    SHELL = "shell"

class AgentAction(BaseModel):
    """
    Represents an action requested by an AI Agent that needs to be intercepted and validated.
    """
    action_type: ActionType = Field(
        ..., 
        description="The target execution environment for the action, e.g., 'sql' or 'shell'"
    )
    command: str = Field(
        ..., 
        description="The actual query or command string to be executed"
    )
    agent_id: str = Field(
        "dummy_agent", 
        description="The unique identifier of the requesting autonomous AI agent"
    )

class SecurityDecision(BaseModel):
    """
    The structured validation decision returned by the Halt Core rule engine.
    """
    approved: bool = Field(
        ..., 
        description="True if the action is approved for execution, False if rejected"
    )
    reason: str = Field(
        ..., 
        description="Explanation detailing why the action was approved or rejected"
    )
    remediation: Optional[str] = Field(
        None, 
        description="An actionable advice or a corrected command suggestion prompting the agent to retry safely"
    )
    rule_triggered: Optional[str] = Field(
        None, 
        description="The name of the security policy/rule that triggered this decision"
    )
    latency_ms: Optional[float] = Field(
        None, 
        description="The execution time of the security evaluation in milliseconds"
    )
