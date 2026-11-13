"""
Sample Python source file for SecureBuild upload testing.
This module contains no real secrets or credentials.
"""

import os
import sys

def greet(name: str) -> str:
    """Return a greeting message."""
    return f"Hello, {name}! Welcome to SecureBuild."


def calculate_risk_score(critical: int, high: int, medium: int, low: int) -> float:
    """
    Calculate a simplified CVSS-like risk score based on vulnerability counts.

    Args:
        critical: Number of critical findings
        high:     Number of high findings
        medium:   Number of medium findings
        low:      Number of low findings

    Returns:
        float: Risk score 0.0–10.0
    """
    score = (critical * 10.0 + high * 7.0 + medium * 4.0 + low * 1.0)
    return min(10.0, round(score / max(1, critical + high + medium + low), 2))


if __name__ == "__main__":
    print(greet("Misbah"))
    score = calculate_risk_score(0, 2, 5, 10)
    print(f"Risk Score: {score}")
