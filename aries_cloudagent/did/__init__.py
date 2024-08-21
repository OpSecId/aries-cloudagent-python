from .key.manager import DidKeyManager
from .web.manager import DidWebManager


class DidOperationError(Exception):
    """Generic DID operation Error."""


__all__ = [
    "DidKeyManager",
    "DidWebManager",
    "DidOperationError",
]
