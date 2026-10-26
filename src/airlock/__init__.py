"""Airlock — an inspection gateway that quarantines prompt injection and data
exfiltration before it reaches a tool-using AI agent."""

from airlock.rules import (
    Decision,
    Direction,
    Event,
    Finding,
    Policy,
    Verdict,
    inspect,
)

__all__ = [
    "Decision",
    "Direction",
    "Event",
    "Finding",
    "Policy",
    "Verdict",
    "inspect",
]

__version__ = "0.1.0"
