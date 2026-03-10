"""
Arcis Core - Shared types

RateLimitEntry dataclass and other shared types.
"""

from dataclasses import dataclass


@dataclass
class RateLimitEntry:
    """Rate limit entry for consistent API across Node.js, Go, and Python."""
    count: int
    reset_time: float
