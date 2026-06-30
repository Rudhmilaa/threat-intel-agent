"""
Security utilities for sanitizing and validating user input.
"""

import re
import json
import logging

logger = logging.getLogger(__name__)

# Dangerous command patterns that should be blocked
DANGEROUS_COMMAND_PATTERNS = [
    r'cmd\s*[/\\]c',  # Windows cmd /c
    r'powershell',  # PowerShell
    r'bash\s+-c',  # bash -c
    r'sh\s+-c',  # sh -c
    r'eval\s*\(',  # eval()
    r'exec\s*\(',  # exec()
    r'subprocess',  # subprocess
    r'os\.system',  # os.system
    r'os\.popen',  # os.popen
    r'base64\s+-d',  # base64 decode
    r'base64Decode',  # base64 decode
    r'curl\s+.*http',  # curl with URL
    r'wget\s+.*http',  # wget with URL
    r'\.exec\s*\(',  # .exec()
    r'\.spawn\s*\(',  # .spawn()
    r'child_process',  # child_process
]

# Dangerous shell operators
DANGEROUS_SHELL_OPERATORS = [
    '|',  # Pipe
    '&&',  # Logical AND
    '||',  # Logical OR
    ';',  # Command separator
    '`',  # Command substitution
    '$',  # Variable expansion (in some contexts)
    '$(',  # Command substitution
]


def contains_dangerous_commands(text: str) -> bool:
    """
    Check if text contains dangerous command patterns.
    
    Args:
        text: Text to check
        
    Returns:
        True if dangerous patterns found, False otherwise
    """
    if not text or not isinstance(text, str):
        return False
    
    text_lower = text.lower()
    
    # Check for dangerous command patterns
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            logger.warning(f"Detected dangerous command pattern: {pattern} in text")
            return True
    
    # Check for dangerous shell operators (if multiple present, likely command injection)
    dangerous_operator_count = sum(1 for op in DANGEROUS_SHELL_OPERATORS if op in text)
    if dangerous_operator_count >= 2:
        logger.warning(f"Detected multiple dangerous shell operators in text")
        return True
    
    return False


def sanitize_honeypot_config(config: dict) -> dict:
    """
    Sanitize honeypot configuration to remove dangerous commands.
    
    Args:
        config: Honeypot configuration dictionary
        
    Returns:
        Sanitized configuration dictionary
    """
    if not isinstance(config, dict):
        return config
    
    sanitized = {}
    
    for key, value in config.items():
        # Skip dangerous fields that might contain commands
        if key.lower() in ['commands', 'command', 'cmd', 'exec', 'script', 'shell']:
            logger.warning(f"Skipping potentially dangerous field: {key}")
            continue
        
        # Recursively sanitize nested dictionaries
        if isinstance(value, dict):
            sanitized[key] = sanitize_honeypot_config(value)
        # Check strings for dangerous commands
        elif isinstance(value, str):
            if contains_dangerous_commands(value):
                logger.warning(f"Removing dangerous command from field: {key}")
                sanitized[key] = ""  # Replace with empty string
            else:
                sanitized[key] = value
        # Check lists for dangerous commands
        elif isinstance(value, list):
            sanitized_list = []
            for item in value:
                if isinstance(item, str) and contains_dangerous_commands(item):
                    logger.warning(f"Removing dangerous command from list in field: {key}")
                    continue  # Skip dangerous items
                elif isinstance(item, dict):
                    sanitized_list.append(sanitize_honeypot_config(item))
                else:
                    sanitized_list.append(item)
            sanitized[key] = sanitized_list
        else:
            sanitized[key] = value
    
    return sanitized


def validate_hp_options(hp_options: dict) -> tuple[bool, str]:
    """
    Validate hp_options to ensure no dangerous commands are present.
    
    Args:
        hp_options: Honeypot options dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(hp_options, dict):
        return False, "hp_options must be a dictionary"
    
    # Convert to JSON string to check for dangerous patterns
    try:
        json_str = json.dumps(hp_options)
        if contains_dangerous_commands(json_str):
            return False, "hp_options contains dangerous command patterns"
    except (TypeError, ValueError) as e:
        logger.warning(f"Failed to serialize hp_options for validation: {e}")
        # Continue with recursive check
    
    # Recursively check all values
    for key, value in hp_options.items():
        if isinstance(value, str) and contains_dangerous_commands(value):
            return False, f"Field '{key}' contains dangerous command patterns"
        elif isinstance(value, dict):
            is_valid, error = validate_hp_options(value)
            if not is_valid:
                return False, error
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and contains_dangerous_commands(item):
                    return False, f"List item in '{key}' contains dangerous command patterns"
                elif isinstance(item, dict):
                    is_valid, error = validate_hp_options(item)
                    if not is_valid:
                        return False, error
    
    return True, ""


def sanitize_deployment_data(deployment_data: dict) -> dict:
    """
    Sanitize deployment data to remove dangerous commands.
    
    Args:
        deployment_data: Deployment data dictionary
        
    Returns:
        Sanitized deployment data dictionary
    """
    if not isinstance(deployment_data, dict):
        return deployment_data
    
    sanitized = {}
    
    for key, value in deployment_data.items():
        if key == 'hp_options':
            # Special handling for hp_options
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                    sanitized[key] = json.dumps(sanitize_honeypot_config(parsed))
                except (json.JSONDecodeError, TypeError):
                    sanitized[key] = value  # Keep as-is if can't parse
            elif isinstance(value, dict):
                sanitized[key] = sanitize_honeypot_config(value)
            else:
                sanitized[key] = value
        elif isinstance(value, dict):
            sanitized[key] = sanitize_deployment_data(value)
        elif isinstance(value, str) and contains_dangerous_commands(value):
            logger.warning(f"Removing dangerous command from deployment field: {key}")
            sanitized[key] = ""
        else:
            sanitized[key] = value
    
    return sanitized

