"""EddsaRdfc2022 cryptosuite."""

from hashlib import sha256
import nacl

from ....wallet.base import BaseWallet
from ....utils.multiformats import multibase
from ....utils.linked_data import CONTEXTS, JsonLdProcessor
from ....core.profile import Profile
from .. import DataIntegrityProofException


class EddsaRdfc2022:
    """EddsaRdfc2022 suite."""

    def __init__(self, *, profile: Profile):
        """Create new EddsaRdfc2022 instance.

        Args:
            profile: Key profile to use.
        """
        super().__init__()
        self.profile = profile

    async def _proof_config(self, document, options):
        proof_config = options.copy()
        
        assert proof_config["type"] == "DataIntegrityProof"
        assert proof_config["cryptosuite"] == "eddsa-rdfc-2022"
        if 'created' in proof_config:
            assert proof_config["created"]
            
        proof_config['@context'] = document['@context']
        return JsonLdProcessor().encode_canonical_rdf(proof_config)

    async def _transformation(self, document, options):
        assert options["type"] == "DataIntegrityProof"
        assert options["cryptosuite"] == "eddsa-rdfc-2022"
        
        return JsonLdProcessor().encode_canonical_rdf(document)
            
    async def _hashing(self, canonical_document, canonical_proof_options):
        return (
            sha256(canonical_document).digest()
            + sha256(canonical_proof_options).digest()
        )

    async def _serialization(self, hash_data, options):
        # https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-eddsa-jcs-2022
        async with self.profile.session() as session:
            did_info = await session.inject(BaseWallet).get_local_did(
                options["verificationMethod"].split("#")[0]
            )
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
        proof_bytes = await wallet.sign_message(
            message=hash_data,
            from_verkey=did_info.verkey,
        )
        return proof_bytes

    async def add_proof(self, document, options):
        # https://www.w3.org/TR/vc-data-integrity/#add-proof
        """Add data integrity proof.

        Args:
            document: The data to sign.
            proof_options: The proof options.

        Returns:
            verification_response: Whether the signature is valid for the data

        """

        existing_proof = document.pop("proof", [])
        assert isinstance(existing_proof, list) or isinstance(existing_proof, dict)
        existing_proof = (
            [existing_proof] if isinstance(existing_proof, dict) else existing_proof
        )

        assert options["type"] == "DataIntegrityProof"
        assert options["cryptosuite"] == "eddsa-rdfc-2022"
        assert options["proofPurpose"]
        assert options["verificationMethod"]
        
        assert document["@context"]

        try:
            document = JsonLdProcessor().inject_context(document, CONTEXTS['security/data-integrity/v2'])
            undefined_types = JsonLdProcessor().find_undefined_types(document)
            undefined_properties = JsonLdProcessor().find_undefined_properties(document)
            undefined_terms = undefined_types + undefined_properties
            if undefined_terms:
                document = JsonLdProcessor().inject_context(document, CONTEXTS['credentials/undefined-terms/v2'])
                # if self.profile.context.settings.get('w3c.auto-inject-context'):
                #     document = jsonld_processor.inject_context(CONTEXTS['credentials/undefined-terms/v2'])
                # else:
                #     raise DataIntegrityProofException(f'Undefined terms: {undefined_terms}')
            
            proof_config = await self._proof_config(document, options)
            document = await self._transformation(document, options)
            hash_data = await self._hashing(document, proof_config)
            proof_bytes = await self._serialization(hash_data, options)

            proof = options.copy()
            proof["proofValue"] = multibase.encode(proof_bytes, "base58btc")

            secured_document = document.copy()
            secured_document["proof"] = existing_proof
            secured_document["proof"].append(proof)

            return secured_document
        
        except Exception:
            raise DataIntegrityProofException()

    async def verify_proof(self, unsecured_document, proof):
        # https://www.w3.org/TR/vc-data-integrity/#verify-proof
        """Verify the data against the proof.

        Args:
            unsecured_document: The data to check.
            proof: The proof.

        Returns:
            verification_response: Whether the signature is valid for the data

        """
        try:
            assert proof["type"] == "DataIntegrityProof"
            assert proof["cryptosuite"] == "eddsa-rdfc-2022"
            assert proof["proofPurpose"]
            assert proof["proofValue"]
            assert proof["verificationMethod"]
        
            assert unsecured_document["@context"]
            
            unsecured_document = JsonLdProcessor().inject_context(unsecured_document, CONTEXTS['security/data-integrity/v2'])
            undefined_document_types = JsonLdProcessor().find_undefined_types(unsecured_document)
            undefined_document_properties = JsonLdProcessor().find_undefined_properties(unsecured_document)
            if undefined_document_types or undefined_document_properties:
                pass
            
            proof_options = proof.copy()
            proof_bytes = multibase.decode(proof_options.pop("proofValue"))

            proof_config = await self._proof_config(document, proof_options)
            document = await self._transformation(document, proof_options)
            hash_data = await self._hashing(document, proof_config)
            
            verification_method = proof["verificationMethod"]
            did = verification_method.split("#")[0]
            if did.split(":")[1] == "key":
                pub_key = multibase.decode(did.split(":")[-1])
                public_key_bytes = bytes(bytearray(pub_key)[2:])
            try:
                nacl.bindings.crypto_sign_open(proof_bytes + hash_data, public_key_bytes)
                return True
            except nacl.exceptions.BadSignatureError:
                return False
        except Exception:
            raise DataIntegrityProofException()
