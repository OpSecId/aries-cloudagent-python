"""EddsaRdfc2022 cryptosuite."""

from pyld import jsonld
from hashlib import sha256

import nacl

from ....utils.multiformats import multibase
from ...document_loader import DocumentLoader
from ..keys import _KeyPair as KeyPair
from ..data_integrity_signature import DataIntegritySignature
from .. import DataIntegrityProofException
from ...resources.constants import SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL


class EddsaRdfc2022(DataIntegritySignature):
    """EddsaRdfc2022 suite."""

    def __init__(self, *, key_pair: KeyPair=None, document_loader: DocumentLoader):
        """Create new EddsaRdfc2022 instance.

        Args:
            key_pair (KeyPair): Key pair to use. Must provide EdDSA signatures
            document_loader (DocumentLoader): Document loader to use.
        """
        super().__init__()
        self.key_pair = key_pair
        self.document_loader = document_loader

    async def _prep_input(self, unsecured_data_document, proof_config):

        try:
            assert proof_config["type"] == "DataIntegrityProof"

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
        """https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-rdfc-2022"""
        # Ensure the Data Integrity context is included
        if (
            SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL
            not in unsecured_data_document["@context"]
        ):
            unsecured_data_document["@context"].append(
                SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL
            )
        proof = proof_config.copy()
        hash_data = await self._prep_input(unsecured_data_document, proof_config)
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

    async def verify_proof(self, unsecured_data_document, proof):
        """Verify the data against the proof.

        Args:
            unsecured_data_document (dict): The document the verify data is derived for as extra context
            proof (dict): The proof to check

        Returns:
            verificationResponse: Whether the signature is valid for the data and a problemDetail object

        """

        if not (isinstance(proof.get("proofValue"), str)):
            raise DataIntegrityProofException(
                'The proof does not contain a valid "proofValue" property.'
            )
        proof_value = proof.pop('proofValue')
        hash_data = await self._prep_input(unsecured_data_document, proof)
        signature = multibase.decode(proof_value)
        
        did = proof["verificationMethod"].split('#')[0]
        # only DID key for now
        if did.split(':')[1] == 'key':
            pub_key = multibase.decode(did.split(':')[-1])
            pub_key = bytes(bytearray(pub_key)[2:])
        elif did.split(':')[1] == 'web':
            pass
            
        try:
            nacl.bindings.crypto_sign_open(signature + hash_data, pub_key)
        except nacl.exceptions.BadSignatureError:
            problem_detail = {
                'type': 'https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR',
                'code': '-65',
                'title': 'BadSignatureError',
                'detail': 'Signature was forged or corrupt.'
            }
            return {
                'verified': False,
                'problem_detail': problem_detail
            }
        return {
                'verified': True,
                'problem_detail': None
            }
