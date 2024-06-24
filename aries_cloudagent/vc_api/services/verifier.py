"""Services for performing Data Integrity Proof signatures over JSON-LD formatted W3C VCs."""

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor
from ...core.profile import Profile
from ...wallet.key_type import ED25519, KeyType
from ..models import (
    VerifiableCredentialSchemaV2,
    VerifiableCredentialV2,
    IssuanceOptions,
    DataIntegrityProof,
    VerifiablePresentation,
)
from ..proofs.validation_result import DocumentVerificationResult

from ..proofs.keys.wallet_key_pair import WalletKeyPair
from ..proofs import (
    CredentialIssuancePurpose,
    DataIntegrityProofException,
)
from ..proofs.suites.ed25519_signature_2020 import Ed25519Signature2020
from ..proofs.purposes.credential_issuance_purpose import CredentialIssuancePurpose

ProofTypes = Union[Type[Ed25519Signature2020]]
SignatureTypes = Union[Type[Ed25519Signature2020],]
SIGNATURE_SUITE_KEY_TYPE_MAPPING: Dict[SignatureTypes, KeyType] = {
    Ed25519Signature2020: ED25519,
}
PROOF_TYPE_SIGNATURE_SUITE_MAPPING: Dict[str, SignatureTypes] = {
    suite.signature_type: suite for suite in SIGNATURE_SUITE_KEY_TYPE_MAPPING
}
PROOF_KEY_TYPE_MAPPING = cast(
    Dict[ProofTypes, KeyType], SIGNATURE_SUITE_KEY_TYPE_MAPPING
)


class VerifierService:
    """VC-API Verifier service."""

    def __init__(self, profile: Profile):
        """Initialize the verifier service."""
        self.profile = profile

    async def _validate_(self, credential):
        errors = VerifiableCredentialSchemaV2().validate(credential)
        if len(errors) > 0:
            raise DataIntegrityProofException(
                f"Credential contains invalid structure: {errors}"
            )

    async def _proof_set_(self, document):

        proof_set = JsonLdProcessor.get_values(document, "proof")

        # If proof_types is present, only take proofs that match
        proof_types = ['ED25519Signature2020']
        if proof_types:
            proof_set = list(filter(lambda _: _["type"] in proof_types, proof_set))

        if len(proof_set) == 0:
            raise DataIntegrityProofException(
                "No matching proofs found in the given document"
            )
        context = document.get("@context")
        proof_set = [{"@context": context, **proof} for proof in proof_set]
        
        return proof_set

    async def _verify_(self, document, proof_set, purpose=CredentialIssuancePurpose()):

        matches = [proof for proof in proof_set if purpose.match(proof)]
        suites = [
            # Satisfy type checks with a cast to LinkedDataProof
            cast(
                DataIntegrityProof,
                # Instantiate suite with a key type
                SuiteClass(
                    key_pair=WalletKeyPair(profile=self.profile, key_type=key_type),
                ),
            )
            # for each suite class -> key_type pair from PROOF_KEY_TYPE_MAPPING
            for SuiteClass, key_type in PROOF_KEY_TYPE_MAPPING.items()
        ]

        if len(suites) == 0:
            raise DataIntegrityProofException("At least one suite is required.")

        if len(matches) == 0:
            raise DataIntegrityProofException("At least one match is required.")

        results = []
        for proof in matches:
            for suite in suites:
                if suite.match_proof(proof.get("type")):
                    result = await suite.verify_proof(
                        proof=proof,
                        document=document,
                        purpose=purpose,
                    )
                    result.proof = proof

                    results.append(result)

        # If no proofs were verified because of no matching suites and purposes
        # throw an error
        if len(results) == 0:
            suite_names = ", ".join([suite.signature_type for suite in suites])
            raise DataIntegrityProofException(
                f"Could not verify any proofs; no proofs matched the required"
                f" suites ({suite_names}) and purpose ({purpose.term})"
            )

    async def verify_credential(
        self, vc: VerifiableCredentialV2, options: IssuanceOptions
    ) -> VerifiableCredentialV2:
        """Verify a VC"""
        # Validate credential
        self._validate_(vc)
        try:
            proof_set = await self._proof_set_(vc.copy())
            
            vc.pop("proof", None)
            # if not purpose:
            purpose = CredentialIssuancePurpose()
            results = await self._verify_(vc, proof_set, purpose)

            # check if all results are valid, create result
            verified = any(result.verified for result in results)
            result = DocumentVerificationResult(
                verified=verified, document=vc, results=results
            )

            # If not valid, extract and optionally add errors to result
            if not verified:
                errors = [result.error for result in results if result.error]

                if len(errors) > 0:
                    result.errors = errors

            return result
        except Exception as e:
            return DocumentVerificationResult(verified=False, document=vc, errors=[e])


    async def verify_presentation(
        self, vp: VerifiablePresentation, options: IssuanceOptions
    ) -> VerifiableCredentialV2:
        """Sign a VC with a Data Integrity Proof."""

        vp = VerifiablePresentation.deserialize(vp)
        options = IssuanceOptions.deserialize(options)