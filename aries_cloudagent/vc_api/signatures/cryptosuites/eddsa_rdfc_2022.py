"""EddsaRdfc2022 cryptosuite."""

from pyld import jsonld
import hashlib

from typing import List

from ....utils.multiformats import multibase
from ...document_loader import DocumentLoader
from ..keys import _KeyPair as KeyPair
from ..data_integrity_signature import DataIntegritySignature
from .. import DataIntegrityProofException

class EddsaRdfc2022(DataIntegritySignature):
    """EddsaRdfc2022 suite."""

    def __init__(self, *, key_pair: KeyPair, document_loader: DocumentLoader):
        """Create new EddsaRdfc2022 instance.

        Args:
            key_pair (KeyPair): Key pair to use. Must provide EdDSA signatures
        """
        super().__init__()
        self.key_pair = key_pair
        self.document_loader = document_loader

    async def create_proof(self, unsecured_data_document, proof_config):
        """https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-rdfc-2022"""
        jsonld.set_document_loader(jsonld.requests_document_loader(timeout=100))
        try:
            assert proof_config["type"] == "DataIntegrityProof"
            assert proof_config["cryptosuite"] == "eddsa-rdfc-2022"
            """https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-rdfc-2022"""
            transformed_data_document = jsonld.normalize(
                unsecured_data_document,
                {
                    "algorithm": "URDNA2015",
                    "format": "application/n-quads",
                    "documentLoader": self.document_loader,
                },
            )

            """https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-rdfc-2022"""
            canonical_proof_config = jsonld.normalize(
                proof_config,
                {
                    "algorithm": "URDNA2015",
                    "format": "application/n-quads",
                    "documentLoader": self.document_loader,
                },
            )

            """https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-rdfc-2022"""
            transformed_document_hash = (
                hashlib.sha256(transformed_data_document.encode()).hexdigest().encode()
            )
            proof_config_hash = (
                hashlib.sha256(canonical_proof_config.encode()).hexdigest().encode()
            )
            hash_data = transformed_document_hash + proof_config_hash

            """https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-eddsa-rdfc-2022"""
            proof_bytes = await self.key_pair.sign(hash_data)

            proof = proof_config.copy()
            proof.pop("@context")
            proof["proofValue"] = multibase.encode(proof_bytes, "base58btc")

            return proof
        except:
            raise DataIntegrityProofException()

    async def sign(self, *, verify_data: bytes, proof: dict) -> dict:
        """Sign the data and add it to the proof.

        Args:
            verify_data (List[bytes]): The data to sign.
            proof (dict): The proof to add the signature to

        Returns:
            dict: The proof object with the added signature

        """
        signature = await self.key_pair.sign(verify_data)

        proof["proofValue"] = multibase.encode(signature, "base58btc")

        return proof

    async def verify_signature(
        self,
        *,
        verify_data: List[bytes],
        verification_method: dict,
        document: dict,
        proof: dict,
        document_loader: DocumentLoader,
    ) -> bool:
        """Verify the data against the proof.

        Args:
            verify_data (bytes): The data to check
            verification_method (dict): The verification method to use.
            document (dict): The document the verify data is derived for as extra context
            proof (dict): The proof to check
            document_loader (DocumentLoader): Document loader used for resolving

        Returns:
            bool: Whether the signature is valid for the data

        """

        if not (isinstance(proof.get("proofValue"), str)):
            raise DataIntegrityProofException(
                'The proof does not contain a valid "proofValue" property.'
            )

        signature = multibase.decode(proof["proofValue"])

        # If the key pair has no public key yet, create a new key pair
        # from the verification method. We don't want to overwrite data
        # on the original key pair
        key_pair = self.key_pair
        if not key_pair.has_public_key:
            key_pair = key_pair.from_verification_method(verification_method)

        return await key_pair.verify(verify_data, signature)
