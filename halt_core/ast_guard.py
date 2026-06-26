import ast
from typing import Tuple

class SecurityViolation(Exception):
    """Exception raised immediately when a security policy violation is detected in the AST."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)

class SecurityVisitor(ast.NodeVisitor):
    """
    AST NodeVisitor that inspects the syntax tree of Python code for security violations.
    Fails fast by raising a SecurityViolation as soon as an unsafe pattern is found.
    """
    def __init__(self):
        # Use sets for O(1) membership lookups
        self.blocked_modules = {
            "subprocess", "importlib", "sys", "pty", 
            "ctypes", "code", "codeop", "runpy", "commands", 
            "builtins", "pdb", "bdb", "sysconfig", "platform",
            "ctypes.util", "inspect", "trace"
        }
        self.blocked_functions = {
            "eval", "exec", "__import__", "compile", "globals", "locals", 
            "getattr", "setattr"
        }
        self.blocked_calls = {
            "system", "popen", "spawn", "rmtree", "Popen", "run", 
            "call", "check_output", "check_call", "getoutput", "getstatusoutput"
        }

    def _flag_violation(self, reason: str) -> None:
        raise SecurityViolation(reason)

    def visit_Import(self, node: ast.Import) -> None:
        for name in node.names:
            root_module = name.name.split('.')[0]
            if root_module in self.blocked_modules:
                self._flag_violation(f"Blocked import of module '{name.name}'")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            root_module = node.module.split('.')[0]
            if root_module in self.blocked_modules:
                self._flag_violation(f"Blocked import from module '{node.module}'")
        for name in node.names:
            if name.name in self.blocked_functions or name.name in self.blocked_calls:
                self._flag_violation(f"Blocked import of dangerous name '{name.name}'")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        # Blocks referencing blocked functions/keywords (e.g. x = eval)
        if node.id in self.blocked_functions:
            self._flag_violation(f"Blocked reference to keyword/builtin '{node.id}'")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Blocks accessing blocked methods/properties (e.g. os.system)
        if node.attr in self.blocked_calls:
            self._flag_violation(f"Blocked access to dangerous attribute/method '{node.attr}'")
        
        # Block double-underscore (dunder) sandbox escape vectors, except __name__
        if node.attr.startswith("__") and node.attr != "__name__":
            self._flag_violation(f"Blocked access to private/dunder attribute '{node.attr}'")
            
        # Walk value if it is a Name (e.g., 'os' in 'os.system')
        if isinstance(node.value, ast.Name):
            if node.value.id in self.blocked_modules:
                self._flag_violation(f"Blocked access to attribute on module '{node.value.id}'")
                
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        
        # Resolve attribute calls (e.g., obj.system)
        if isinstance(func, ast.Attribute):
            if func.attr in self.blocked_calls:
                self._flag_violation(f"Blocked call to dangerous method '{func.attr}'")
        # Resolve direct calls (e.g., eval())
        elif isinstance(func, ast.Name):
            if func.id in self.blocked_functions:
                self._flag_violation(f"Blocked call to keyword/builtin '{func.id}'")
                
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Block defining functions with names matching blocked functions or calls
        if node.name in self.blocked_functions or node.name in self.blocked_calls:
            self._flag_violation(f"Blocked definition of function with name '{node.name}'")
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Block defining classes with names matching blocked modules/functions
        if node.name in self.blocked_functions or node.name in self.blocked_modules:
            self._flag_violation(f"Blocked definition of class with name '{node.name}'")
        self.generic_visit(node)

def is_safe_python_code(code_str: str) -> Tuple[bool, str]:
    """
    Parses a dynamically generated Python code string using the ast module.
    Detects and blocks destructive imports, attributes, and calls.
    
    Args:
        code_str (str): The Python code to parse and audit.
        
    Returns:
        Tuple[bool, str]: (is_safe, reason)
    """
    try:
        tree = ast.parse(code_str)
    except SyntaxError as e:
        return False, f"SyntaxError: {e.msg} on line {e.lineno}"
    except Exception as e:
        return False, f"Failed to parse AST: {str(e)}"

    visitor = SecurityVisitor()
    try:
        visitor.visit(tree)
    except SecurityViolation as violation:
        return False, violation.reason

    return True, "Python code is safe."
