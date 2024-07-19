"""EddsaJcs2022 cryptosuite."""

from pyld import jsonld
from hashlib import sha256
import canonicaljson

from typing import List

from ....utils.multiformats import multibase
from ...document_loader import DocumentLoader
from ..keys import _KeyPair as KeyPair
from ..data_integrity_signature import DataIntegritySignature
from .. import DataIntegrityProofException
from ...resources.constants import SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL


class EddsaJcs2022(DataIntegritySignature):
    """EddsaJcs2022 suite."""

    def __init__(self, *, key_pair: KeyPair, document_loader: DocumentLoader):
        """Create new EddsaJcs2022 instance.

        Args:
            key_pair (KeyPair): Key pair to use. Must provide EdDSA signatures
        """
        super().__init__()
        self.key_pair = key_pair
        self.document_loader = document_loader

    async def create_proof(self, unsecured_data_document, proof_config):
        """https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022"""
        # Ensure the Data Integrity context is included
        if (
            SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL
            not in unsecured_data_document["@context"]
        ):
            unsecured_data_document["@context"].append(
                SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL
            )
        proof = proof_config.copy()
        try:

            """https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022"""
            proof_config["@context"] = unsecured_data_document["@context"]
            assert proof_config["type"] == "DataIntegrityProof"
            assert proof_config["cryptosuite"] == "eddsa-jcs-2022"
            canonical_proof_config = canonicaljson.encode_canonical_json(proof_config)

            """https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-jcs-2022"""
            transformed_data_document = canonicaljson.encode_canonical_json(
                unsecured_data_document
            )

            """https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022"""
            hash_data = (
                sha256(canonical_proof_config).digest()
                + sha256(transformed_data_document).digest()
            )

            """https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-eddsa-jcs-2022"""
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

    async def verify_proof(
        self,
        *,
        verify_data: List[bytes],
        verification_method: dict,
        document: dict,
        proof: dict,
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
        """https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022"""
        jsonld.set_document_loader(jsonld.requests_document_loader(timeout=100))

        if not (isinstance(proof.get("proofValue"), str)):
            raise DataIntegrityProofException(
                'The proof does not contain a valid "proofValue" property.'
            )

        signature = multibase.decode(proof["proofValue"])

        return await self.key_pair.verify(verify_data, signature)
