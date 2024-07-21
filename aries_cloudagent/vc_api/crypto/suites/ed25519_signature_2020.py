"""Ed25519Signature2020 cryptosuite."""

from pyld import jsonld
from hashlib import sha256
import nacl

from typing import List

from ....utils.multiformats import multibase
from ...document_loader import DocumentLoader
from ..keys import _KeyPair as KeyPair
from ..di_signature import DataIntegritySignature
from .. import DataIntegrityProofException
from ...resources.constants import (
    SECURITY_CONTEXT_ED25519_2020_URL,
)


class Ed25519Signature2020(DataIntegritySignature):
    """Ed25519Signature2020 suite."""

    def __init__(self, *, key_pair: KeyPair = None, document_loader: DocumentLoader):
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

    async def add_proof(self, unsecured_data_document, proof_config):
        """https://www.w3.org/TR/vc-di-eddsa/#add-proof-ed25519signature2020"""

        # Add suite context url if not present
        if SECURITY_CONTEXT_ED25519_2020_URL not in unsecured_data_document["@context"]:
            unsecured_data_document["@context"].append(
                SECURITY_CONTEXT_ED25519_2020_URL
            )

        hash_data = await self._prep_input(unsecured_data_document, proof_config)

        """https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-ed25519signature2020"""
        # Sign the bytes with eddsa key pair
        try:
            proof = proof_config.copy()
            proof.pop("@context")
            proof_bytes = await self.key_pair.sign(hash_data)
            proof["proofValue"] = multibase.encode(proof_bytes, "base58btc")

            secured_document = unsecured_data_document.copy()
            secured_document["proof"] = proof

            return secured_document
        except:
            raise DataIntegrityProofException()

    async def verify_proof(self, unsecured_data_document, proof) -> bool:
        """Verify the data against the proof.

        Args:
            unsecured_data_document (dict): The unsecured data document to verify
            proof (dict): The proof to check

        Returns:
            bool: Whether the signature is valid for the data

        """
        proof_value = proof.pop("proofValue")
        hash_data = await self._prep_input(unsecured_data_document, proof)
        signature = multibase.decode(proof_value)

        did = proof["verificationMethod"].split("#")[0]

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
