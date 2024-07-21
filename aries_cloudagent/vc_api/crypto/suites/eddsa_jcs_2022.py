"""EddsaJcs2022 cryptosuite."""

from pyld import jsonld
from hashlib import sha256
import canonicaljson
import nacl

from typing import List

from ....utils.multiformats import multibase
from ...document_loader import DocumentLoader
from ..keys import _KeyPair as KeyPair
from ..di_signature import DataIntegritySignature
from .. import DataIntegrityProofException
from ...resources.constants import (
    CREDENTIALS_CONTEXT_V2_URL,
    SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL,
)


class EddsaJcs2022(DataIntegritySignature):
    """EddsaJcs2022 suite."""

    def __init__(self, *, key_pair: KeyPair = None, document_loader: DocumentLoader):
        """Create new EddsaJcs2022 instance.

        Args:
            key_pair (KeyPair): Key pair to use. Must provide EdDSA signatures
        """
        super().__init__()
        self.key_pair = key_pair
        self.document_loader = document_loader

    async def _prep_input(self, unsecured_data_document, proof_config):
        try:
            """https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022"""
            canonical_proof_config = canonicaljson.encode_canonical_json(proof_config)

            """https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-jcs-2022"""
            transformed_data_document = canonicaljson.encode_canonical_json(
                unsecured_data_document
            )

            """https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022"""
            return (
                sha256(canonical_proof_config).digest()
                + sha256(transformed_data_document).digest()
            )
        except:
            raise DataIntegrityProofException()

    async def add_proof(self, unsecured_data_document, proof_config):
        """https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022"""

        assert proof_config["type"] == "DataIntegrityProof"
        assert proof_config["cryptosuite"] == "eddsa-jcs-2022"

        # Ensure the Data Integrity context is included for vcdm 1.1
        if (
            SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL
            not in unsecured_data_document["@context"]
            and unsecured_data_document["@context"][0] != CREDENTIALS_CONTEXT_V2_URL
        ):
            unsecured_data_document["@context"].append(
                SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL
            )

        hash_data = await self._prep_input(unsecured_data_document, proof_config)

        """https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-eddsa-jcs-2022"""
        try:
            proof = proof_config.copy()
            proof_bytes = await self.key_pair.sign(hash_data)
            proof["proofValue"] = multibase.encode(proof_bytes, "base58btc")

            secured_document = unsecured_data_document.copy()
            secured_document["proof"] = proof

            return secured_document
        except:
            raise DataIntegrityProofException()

    async def verify_proof(self, unsecured_data_document, proof):
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

        if not (isinstance(proof.get("proofValue"), str)):
            raise DataIntegrityProofException(
                'The proof does not contain a valid "proofValue" property.'
            )

        signature = multibase.decode(proof["proofValue"])
        proof_value = proof.pop("proofValue")
        hash_data = await self._prep_input(unsecured_data_document, proof)
        signature = multibase.decode(proof_value)
        did = proof["verificationMethod"].split("#")[0]
        # only DID key for now
        if did.split(":")[1] == "key":
            pub_key = multibase.decode(did.split(":")[-1])
            pub_key = bytes(bytearray(pub_key)[2:])

        try:
            nacl.bindings.crypto_sign_open(signature + hash_data, pub_key)
            return {"verified": True, "problem_detail": None}
        except nacl.exceptions.BadSignatureError:
            return {
                "verified": False,
                "problem_detail": {
                    "type": "https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR",
                    "code": "-65",
                    "title": "BadSignatureError",
                    "detail": "Signature was forged or corrupt.",
                },
            }
