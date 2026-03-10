"""
Arcis Core - Error classes

InputTooLargeError and ValidationError exception classes.
"""

from typing import List


class InputTooLargeError(Exception):
    """Exception raised when input exceeds maximum size."""
    def __init__(self, size: int, max_size: int):
        self.size = size
        self.max_size = max_size
        super().__init__(f"Input size {size} exceeds maximum of {max_size} bytes")


class ValidationError(Exception):
    """Exception raised when validation fails."""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(", ".join(errors))
