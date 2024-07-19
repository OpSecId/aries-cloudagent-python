"""Ed25519Signature2020 cryptosuite."""

from pyld import jsonld
from hashlib import sha256

from typing import List

from ....utils.multiformats import multibase
from ...document_loader import DocumentLoader
from ..keys import _KeyPair as KeyPair
from ..data_integrity_signature import DataIntegritySignature
from .. import DataIntegrityProofException
from ...resources.constants import (
    SECURITY_CONTEXT_ED25519_2020_URL,
)


class Ed25519Signature2020(DataIntegritySignature):
    """Ed25519Signature2020 suite."""

    def __init__(self, *, key_pair: KeyPair, document_loader: DocumentLoader):
        """Create new Ed25519Signature2020 instance.

        Args:
            key_pair (KeyPair): Key pair to use. Must provide EdDSA signatures
            document_loader (DocumentLoader): Document loader to use
        """
        super().__init__()
        self.key_pair = key_pair
        self.document_loader = document_loader

    async def _prep_input(self, unsecured_data_document, proof_config):

        try:
            assert proof_config["type"] == "Ed25519Signature2020"

            """https://www.w3.org/TR/vc-di-eddsa/#transformation-ed25519signature2020"""
            # Transform (normalize) document to canon rdf dataset w/ n-quads
            transformed_data_document = jsonld.normalize(
                unsecured_data_document,
                {
                    "algorithm": "URDNA2015",
                    "format": "application/n-quads",
                    "documentLoader": self.document_loader,
                },
            )

            """https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-ed25519signature2020"""
            # Transform (normalize) proof config to canon rdf dataset w/ n-quads
            proof_config["@context"] = unsecured_data_document["@context"]
            canonical_proof_config = jsonld.normalize(
                proof_config,
                {
                    "algorithm": "URDNA2015",
                    "format": "application/n-quads",
                    "documentLoader": self.document_loader,
                },
            )

            if transformed_data_document == "":
                raise DataIntegrityProofException("Couldn't normalize input document")
            if canonical_proof_config == "":
                raise DataIntegrityProofException("Couldn't normalize proof config")

            """https://www.w3.org/TR/vc-di-eddsa/#hashing-ed25519signature2020"""
            # Concatenate sha256 hash from both transformed inputs
            hash_data = (
                sha256(canonical_proof_config.encode("utf-8")).digest()
                + sha256(transformed_data_document.encode("utf-8")).digest()
            )

            return hash_data
        except:
            raise DataIntegrityProofException()

    async def create_proof(self, unsecured_data_document, proof_config):
        """https://www.w3.org/TR/vc-di-eddsa/#add-proof-ed25519signature2020"""

        # Add relevant context url if not present
        if SECURITY_CONTEXT_ED25519_2020_URL not in unsecured_data_document["@context"]:
            unsecured_data_document["@context"].append(
                SECURITY_CONTEXT_ED25519_2020_URL
            )
        # Since Ed25519Signature2020 doesn't use the cryptosuite property,
        # we map it to the type and ensure the correct value is set
        proof_config["type"] = proof_config.pop("cryptosuite")
        proof = proof_config.copy()
        hash_data = await self._prep_input(unsecured_data_document, proof_config)

        """https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-ed25519signature2020"""
        # Sign the bytes with eddsa key pair
        try:
            proof_bytes = await self.key_pair.sign(hash_data)
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

    async def verify_proof(self, unsecured_data_document, proof) -> bool:
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
        hash_data = await self._prep_input(unsecured_data_document, proof)
        signature = multibase.decode(proof["proofValue"])

        verification = await self.key_pair.verify(hash_data, signature)

        return verification
        # return {}