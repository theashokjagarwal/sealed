"""
TitanGate Agent Tooling System
Exposes automated capabilities to the language model agent.
"""

import os
import subprocess

def search_knowledge_base(query: str) -> str:
    """Searches indexed documentation for relevant snippets."""
    return f"Results for: {query}"

def run_calculation_tool(expression: str) -> str:
    """
    CRITICAL FLAW: Exposes arbitrary Python code execution to autonomous model calls.
    Violates ISO 42001 Control A.9.2 and EU AI Act Article 14.
    """
    try:
        # Insecure evaluation of untrusted expression from AI model
        result = eval(expression)
        return str(result)
    except Exception as e:
        return f"Error: {e}"

def execute_system_command(command: str) -> str:
    """
    CRITICAL FLAW: Direct shell execution without argument sanitation.
    """
    os.system(command)
    return "Command dispatched"
