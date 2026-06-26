import shlex
import re
from typing import Tuple, Set, List, Optional

# Match valid environment variable assignments at start of a command segment (e.g. VAR=val)
VAR_ASSIGN_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*=')

DEFAULT_DENY_LIST = {
    "rm", "wget", "curl", "chmod", "sudo", "chown", "mv", "dd", "mkfs", 
    "shutdown", "reboot", "poweroff", "init", "systemctl", "ufw", "iptables"
}

WRAPPERS = {"sudo", "env", "nohup", "setsid", "exec", "xargs"}
SEPARATORS = {"&&", "||", "|", ";", "&", "\n"}
SHELL_EXECUTORS = {
    "sh", "bash", "zsh", "cmd", "powershell", "pwsh", "cmd.exe", "powershell.exe", "tclsh", "wish"
}

def get_basename(cmd_path: str) -> str:
    """Extracts the utility/command name from a path, supporting both slashes."""
    return cmd_path.replace('\\', '/').split('/')[-1]

def extract_utilities(segment: List[str]) -> List[str]:
    """
    Given a command segment (list of tokens), extracts the utility names to check.
    It skips variable assignments (VAR=val), brackets/quotes, and unwraps wrappers.
    
    Example: ['sudo', 'VAR=val', '/bin/rm', '-rf'] -> ['sudo', 'rm']
    """
    utilities = []
    i = 0
    while i < len(segment):
        token = segment[i]
        # Skip subshell, bracket symbols or quotes that might be parsed as tokens
        if token in {'(', ')', '[', ']', '{', '}', '$', '`', '"', "'"}:
            i += 1
            continue
        
        # Skip environment variable assignments
        if VAR_ASSIGN_RE.match(token):
            i += 1
            continue
            
        basename = get_basename(token)
        # Avoid empty strings or redirection tokens
        if not basename or basename in {'<', '>', '>>', '2>&1', '1>&2', '&'}:
            i += 1
            continue
            
        utilities.append(basename)
        
        # If it's a wrapper, keep looking for the next utility in the same segment
        if basename in WRAPPERS:
            i += 1
            # Skip any variable assignments that might follow a wrapper (e.g. env VAR=val rm)
            while i < len(segment) and VAR_ASSIGN_RE.match(segment[i]):
                i += 1
            continue
        else:
            # Found the main executable of this segment; subsequent tokens are arguments.
            break
            
    return utilities

def split_into_segments(tokens: List[str]) -> List[List[str]]:
    """
    Splits a list of shlex tokens into separate command segments based on separators.
    Separators are: &&, ||, |, ;, &, \n
    """
    segments = []
    current_segment = []
    for token in tokens:
        if token in SEPARATORS:
            if current_segment:
                segments.append(current_segment)
                current_segment = []
        else:
            current_segment.append(token)
    if current_segment:
        segments.append(current_segment)
    return segments

def is_safe_shell_command(command_str: str, deny_list: Optional[Set[str]] = None) -> Tuple[bool, str]:
    """
    Parses complex, chained shell commands and validates them against a deny-list.
    Handles splitting on &&, ||, |, ;, and recursively inspects nested shell executions.
    
    Args:
        command_str (str): The shell command string to inspect.
        deny_list (set): Optional custom set of denied command basenames.
        
    Returns:
        Tuple[bool, str]: (is_safe, reason)
    """
    if deny_list is None:
        deny_list = DEFAULT_DENY_LIST

    command_str = command_str.strip()
    if not command_str:
        return True, "Empty shell command."

    try:
        # Tokenize with punctuation characters to handle operators and subshells cleanly
        lexer = shlex.shlex(command_str, posix=True, punctuation_chars=True)
        tokens = list(lexer)
    except ValueError as e:
        # Unbalanced quotes or parsing issues can indicate shell injection/obfuscation
        return False, f"Shell tokenization error (possible obfuscation/malformed input): {str(e)}"
    except Exception as e:
        return False, f"Failed to tokenize command: {str(e)}"

    # Split tokens into segments based on shell operators: &&, ||, |, ;, &
    segments = split_into_segments(tokens)

    for segment in segments:
        utilities = extract_utilities(segment)
        for utility in utilities:
            # Normalize to lowercase for case-insensitive check
            normalized_util = utility.lower()
            if normalized_util in deny_list:
                return False, f"Blocked command utility detected: '{utility}'"
            
            # Recursively inspect command strings passed to shell executors (e.g. bash -c "cmd")
            if normalized_util in SHELL_EXECUTORS:
                for idx, tok in enumerate(segment):
                    # Standard shell argument flags that accept command strings
                    if tok.lower() in {"-c", "--c", "/c", "/k", "-command", "-cmd"}:
                        if idx + 1 < len(segment):
                            nested_cmd = segment[idx + 1]
                            safe, reason = is_safe_shell_command(nested_cmd, deny_list)
                            if not safe:
                                return False, f"Nested shell command violation: {reason}"
                                
            # Recursively inspect inline python code (e.g. python -c "...")
            elif normalized_util in {"python", "python3", "python.exe", "python3.exe"}:
                for idx, tok in enumerate(segment):
                    if tok == "-c":
                        if idx + 1 < len(segment):
                            inline_code = segment[idx + 1]
                            from halt_core.ast_guard import is_safe_python_code
                            safe, reason = is_safe_python_code(inline_code)
                            if not safe:
                                return False, f"Inline Python AST violation: {reason}"

    return True, "Shell command is safe."
