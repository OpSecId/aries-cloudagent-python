from .data_integrity_proof import DataIntegrityProof
from .data_integrity_signature import DataIntegritySignature

# from .error import DataIntegrityProofException


class DataIntegrityProofException(Exception):
    """Base exception for linked data proof module."""


__all__ = [
    "DataIntegrityProof",
    "DataIntegrityProofException",
    "DataIntegritySignature",
]
