import unittest
import os
import json
import io
import logging
from halt_core.config import config
from halt_core.shell_parser import is_safe_shell_command
from halt_core.ast_guard import is_safe_python_code
from halt_core.interceptor.middleware import CommandInterceptor, StructuredJSONFormatter
from halt_core.interceptor.engine import RuleEngine
from halt_core.interceptor.memory import MemoryManager
from halt_core.interceptor.rules.shell_rules import ShellDenyListRule
from halt_core.models.schemas import AgentAction, ActionType

class TestConfigurationLoading(unittest.TestCase):
    def setUp(self):
        # Backup defaults
        self.original_deny_commands = set(config.deny_commands)
        self.original_blocked_modules = set(config.blocked_modules)
        
    def tearDown(self):
        # Restore defaults
        config.reset_to_defaults()
        if os.path.exists("halt_config.json"):
            os.remove("halt_config.json")

    def test_dynamic_config_override(self):
        # Create a custom config file that blocks 'echo' but allows 'rm'
        custom_config = {
            "deny_commands": ["echo"],
            "blocked_modules": ["math"]
        }
        
        with open("halt_config.json", "w", encoding="utf-8") as f:
            json.dump(custom_config, f)
            
        # Trigger config reload
        config.load_config()
        
        # Verify shell parser uses custom deny list
        safe, reason = is_safe_shell_command("rm -rf /")
        self.assertTrue(safe, "rm should be allowed by custom config")
        
        safe, reason = is_safe_shell_command("echo hello")
        self.assertFalse(safe, "echo should be blocked by custom config")
        self.assertIn("blocked command utility", reason.lower())
        
        # Verify ast guard uses custom blocked modules list
        safe, reason = is_safe_python_code("import os")
        self.assertTrue(safe, "os import should be allowed now")
        
        safe, reason = is_safe_python_code("import math")
        self.assertFalse(safe, "math import should be blocked by custom config")
        self.assertIn("blocked import of module", reason.lower())


class TestStructuredLogging(unittest.TestCase):
    def setUp(self):
        # Set up a stream capture handler
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setFormatter(StructuredJSONFormatter())
        
        self.logger = logging.getLogger("halt_core.interceptor")
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.INFO)
        
        # Initialize interceptor
        rules = [ShellDenyListRule()]
        engine = RuleEngine(rules=rules)
        memory = MemoryManager()
        self.interceptor = CommandInterceptor(rule_engine=engine, memory_manager=memory)

    def tearDown(self):
        self.logger.removeHandler(self.handler)

    def test_structured_json_output(self):
        # 1. Trigger an approved action
        action_ok = AgentAction(
            action_type=ActionType.SHELL,
            command="ls -la",
            agent_id="Agent-Structured-Ok"
        )
        self.interceptor.intercept(action_ok)
        
        # Read and verify log line
        log_output = self.log_stream.getvalue().strip().splitlines()
        self.assertTrue(len(log_output) > 0)
        
        log_line = log_output[0]
        # Verify it is valid JSON
        try:
            log_data = json.loads(log_line)
        except json.JSONDecodeError:
            self.fail("Log output is not valid JSON")
            
        # Assert expected fields
        self.assertIn("timestamp", log_data)
        self.assertEqual(log_data["level"], "INFO")
        self.assertEqual(log_data["agent_id"], "Agent-Structured-Ok")
        self.assertEqual(log_data["action_type"], "shell")
        self.assertEqual(log_data["command"], "ls -la")
        self.assertTrue(log_data["approved"])
        self.assertEqual(log_data["rule_triggered"], "RuleEngine")
        self.assertIn("latency_ms", log_data)
        self.assertTrue(isinstance(log_data["latency_ms"], float))

        # Clear buffer
        self.log_stream.truncate(0)
        self.log_stream.seek(0)

        # 2. Trigger a rejected action
        action_bad = AgentAction(
            action_type=ActionType.SHELL,
            command="rm -rf /",
            agent_id="Agent-Structured-Bad"
        )
        self.interceptor.intercept(action_bad)
        
        log_output_bad = self.log_stream.getvalue().strip().splitlines()
        self.assertTrue(len(log_output_bad) > 0)
        
        log_line_bad = log_output_bad[0]
        log_data_bad = json.loads(log_line_bad)
        
        self.assertEqual(log_data_bad["level"], "WARNING")
        self.assertEqual(log_data_bad["agent_id"], "Agent-Structured-Bad")
        self.assertEqual(log_data_bad["command"], "rm -rf /")
        self.assertFalse(log_data_bad["approved"])
        self.assertEqual(log_data_bad["rule_triggered"], "ShellDenyListRule")
        self.assertIn("remediation", log_data_bad)

if __name__ == "__main__":
    unittest.main()
