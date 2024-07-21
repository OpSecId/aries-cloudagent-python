from typing import Dict, Type, Union, cast
from pyld.jsonld import JsonLdProcessor
from ...core.profile import Profile
from ..models import (
    CredentialBase,
    PresentationBase,
    VerifiableCredentialBase,
    VerifiableCredentialBaseSchema,
    VerificationOptions,
    DIProof,
)
from ..crypto.keys.wallet_key_pair import WalletKeyPair
from ..crypto.purposes.assertion_proof_purpose import AssertionProofPurpose

from ..document_loader import DocumentLoader
from ..crypto.validation_result import DocumentVerificationResult
from ..crypto.suites import CRYPTOSUITES


class VerifierServiceError(Exception):
    """Generic Service Error."""


class VerifierService:
    """Class for verifying W3C VCs."""

    def __init__(self, profile: Profile):
        """Initialize the VC LD Proof Manager."""
        self.profile = profile

    async def _verify_di_proof(
        self, vc: VerifiableCredentialBase, options: VerificationOptions
    ) -> DocumentVerificationResult:
        # Instantiate cryptosuite class
        proof = vc.pop("proof")
        try:
            suite = CRYPTOSUITES[options.cryptosuite](
                key_pair=WalletKeyPair(
                    profile=self.profile,
                    key_type=CRYPTOSUITES[vc.proof.cryptosuite]["key_type"],
                ).from_verification_method(vc.proof.verification_method)
            )
        except:
            raise VerifierServiceError('Invalid cryptosuite')
        verification = suite.verify_proof(vc.serialize())
        return verification
    
    async def _validate_proof(self, proof, options):

        if options.expected_proof_purpose \
            and options.expected_proof_purpose != proof.proof_purpose:
            raise VerifierServiceError("Unexpected proof purpose")

        if (options.domain and proof.domain) \
            and options.domain != proof.domain:
            raise VerifierServiceError("Domain mismatch")

        if (options.challenge and proof.challenge) \
            and options.challenge != proof.challenge:
            raise VerifierServiceError("Challenge mismatch")
        
        if proof.proof_value:
            pass
    
    async def _get_crypto_suite(self, proof):

        if proof.type == "DataIntegrityProof":
            if not proof.cryptosuite:
                raise VerifierServiceError("Missing cryptosuite for DataIntegrityProof")
            suite_label = proof.cryptosuite

        elif proof.type in ["Ed25519Signature2020"]:
            suite_label = proof.type
        try:
            return CRYPTOSUITES[suite_label]["suite"](
                document_loader=DocumentLoader(self.profile),
            )
        except:
            raise VerifierServiceError('Invalid cryptosuite')

    async def verify_credential(
        self, vc: VerifiableCredentialBase, options: VerificationOptions
    ) -> DocumentVerificationResult:
        """Verify a Verifiable Credential."""

        credential = vc.serialize().copy()
        proof = credential.pop('proof', None)
        
        verification_result = {
            "verified": False,
            "verifiedDocument": credential,
            "errors": [],
            "warnings": [],
        }

        # validation_errors = VerifiableCredentialBaseSchema().validate(vc)
        # if len(validation_errors) > 0:
        #     raise DataIntegrityProofException(
        #         f"Unable to verify credential with invalid structure: {validation_errors}"
        #     )
        
        if not vc.issuer_id:
            raise VerifierServiceError("VC issuer id is required")

        if not vc.credential_subject:
            raise VerifierServiceError("Credential subject is required")

        if not vc.proof.verification_method:
            raise VerifierServiceError("Verification method subject is required")
        
        await self._validate_proof(vc.proof, options)
        
        # if 'EnvelopedVerifiableCredential' in vc.type:
        #     credential_b64 = vc.id.split(';')[-1]
        #     credential = base64.urlsafe_b64decode(credential_b64.encode()).decode()
        
        suite = await self._get_crypto_suite(vc.proof)
        
        proof_verification = await suite.verify_proof(credential, proof)

        verification_result["verified"] = proof_verification["verified"]

        if proof_verification["problem_detail"]:
            verification_result["errors"].append(proof_verification["problem_detail"])

        if "credentialStatus" in credential:
            pass

        if "validFrom" in credential:
            pass

        if "validUntil" in credential:
            pass

        return verification_result

    async def verify_presentation(
        self, vp: PresentationBase, options: VerificationOptions
    ) -> DocumentVerificationResult:
        """Verify a Verifiable Credential."""

        presentation = vp.serialize().copy()
        proof = presentation.pop('proof', None)
        
        verification_result = {
            "verified": False,
            "verifiedDocument": presentation,
            "errors": [],
            "warnings": [],
        }

        # validation_errors = VerifiableCredentialBaseSchema().validate(vc)
        # if len(validation_errors) > 0:
        #     raise DataIntegrityProofException(
        #         f"Unable to verify credential with invalid structure: {validation_errors}"
        #     )

        if vp.verifiable_credential:
            credentials = [vp.verifiable_credential] if isinstance(vp.verifiable_credential, dict) else vp.verifiable_credential
            for credential in credentials:
                try:
                    CredentialBase.deserialize(credential)
                except:
                    raise VerifierServiceError("Credential subject is required")

        if not vp.proof.verification_method:
            raise VerifierServiceError("Verification method subject is required")
        
        await self._validate_proof(vp.proof, options)
        
        suite = self._get_crypto_suite(vp.proof)
        
        proof_verification = await suite.verify_proof(presentation, proof)

        verification_result["verified"] = proof_verification["verified"]

        if proof_verification["problem_detail"]:
            verification_result["errors"].append(proof_verification["problem_detail"])

        return verification_result