from collections import deque
from threading import Lock
from typing import Dict, List
from halt_core.models.schemas import AgentAction

class MemoryManager:
    """
    In-memory state tracker for Halt Core.
    Maintains a thread-safe, rolling window of recent actions executed by each agent.
    """

    def __init__(self, max_size: int = 10):
        self._max_size = max_size
        self._history: Dict[str, deque] = {}
        self._lock = Lock()

    def add_action(self, agent_id: str, action: AgentAction) -> None:
        """
        Appends a successfully validated action to the agent's context history.
        
        Args:
            agent_id (str): The requesting agent identifier.
            action (AgentAction): The action details.
        """
        with self._lock:
            if agent_id not in self._history:
                self._history[agent_id] = deque(maxlen=self._max_size)
            self._history[agent_id].append(action)

    def get_history(self, agent_id: str) -> List[AgentAction]:
        """
        Retrieves a copy of the recent action history sequence for a specific agent.
        
        Args:
            agent_id (str): The requesting agent identifier.
            
        Returns:
            List[AgentAction]: A list of previous actions from oldest to newest.
        """
        with self._lock:
            if agent_id not in self._history:
                return []
            return list(self._history[agent_id])

    def clear(self, agent_id: str) -> None:
        """
        Resets and clears all context history for a given agent.
        
        Args:
            agent_id (str): The requesting agent identifier.
        """
        with self._lock:
            if agent_id in self._history:
                self._history[agent_id].clear()
