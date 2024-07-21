"""Abstract base class for linked data proofs."""

from abc import ABC
from typing import ClassVar, List, Optional, Union

from pyld import jsonld
from typing_extensions import TypedDict

from .check import get_properties_without_context
from ..resources.constants import SECURITY_CONTEXT_URL
from ..document_loader import DocumentLoaderMethod

# from ..signatures import DataIntegrityProofException, DataIntegrityProof
from .error import DataIntegrityProofException
from .purposes import _ProofPurpose as ProofPurpose
from .validation_result import ProofResult


class DataIntegrityProof(ABC):
    """Base Linked data proof."""

    def __init__(
        self,
        *,
        proof_config: Optional[dict] = None,
    ):
        """Initialize new DataIntegrityProof instance."""
        self.proof_config = proof_config

    async def add_proof(
        self,
        *,
        document: dict,
        proof_config: dict,
        purpose: ProofPurpose,
        document_loader: DocumentLoaderMethod,
    ) -> dict:
        """Create proof for document.

        Args:
            document (dict): The document to create the proof for
            purpose (ProofPurpose): The proof purpose to include in the proof
            document_loader (DocumentLoader): Document loader used for resolving

        Returns:
            dict: The proof object

        """
        raise DataIntegrityProofException(
            f"{self.signature_type} signature suite does not support creating proofs"
        )

    async def verify_proof(
        self,
        *,
        proof: dict,
        document: dict,
        purpose: ProofPurpose,
        document_loader: DocumentLoaderMethod,
    ) -> ProofResult:
        """Verify proof against document and proof purpose.

        Args:
            proof (dict): The proof to verify
            document (dict): The document to verify the proof against
            purpose (ProofPurpose): The proof purpose to verify the proof against
            document_loader (DocumentLoader): Document loader used for resolving

        Returns:
            ValidationResult: The results of the proof verification

        """
        raise DataIntegrityProofException(
            f"{self.signature_type} signature suite does not support verifying proofs"
        )

    def _canonize(self, *, input, document_loader: DocumentLoaderMethod) -> str:
        """Canonize input document using URDNA2015 algorithm."""
        # application/n-quads format always returns str
        missing_properties = get_properties_without_context(input, document_loader)

        if len(missing_properties) > 0:
            raise DataIntegrityProofException(
                f"{len(missing_properties)} attributes dropped. "
                f"Provide definitions in context to correct. {missing_properties}"
            )

        return jsonld.normalize(
            input,
            {
                "algorithm": "URDNA2015",
                "format": "application/n-quads",
                "documentLoader": document_loader,
            },
        )

    def _get_verification_method(
        self, *, proof: dict, document_loader: DocumentLoaderMethod
    ) -> dict:
        """Get verification method for proof."""

        verification_method = proof.get("verificationMethod")

        if isinstance(verification_method, dict):
            verification_method: str = verification_method.get("id")

        if not verification_method:
            raise DataIntegrityProofException('No "verificationMethod" found in proof')

        # TODO: This should optionally use the context of the document?
        framed = jsonld.frame(
            verification_method,
            frame={
                "@context": SECURITY_CONTEXT_URL,
                "@embed": "@always",
                "id": verification_method,
            },
            options={
                "documentLoader": document_loader,
                "expandContext": SECURITY_CONTEXT_URL,
                # if we don't set base explicitly it will remove the base in returned
                # document (e.g. use key:z... instead of did:key:z...)
                # same as compactToRelative in jsonld.js
                "base": None,
            },
        )

        if not framed:
            raise DataIntegrityProofException(
                f"Verification method {verification_method} not found"
            )

        if framed.get("revoked"):
            raise DataIntegrityProofException(
                "The verification method has been revoked."
            )

        return framed

    def match_proof(self, signature_type: str) -> bool:
        """Match signature type to signature type of this suite."""
        return signature_type == self.signature_type
