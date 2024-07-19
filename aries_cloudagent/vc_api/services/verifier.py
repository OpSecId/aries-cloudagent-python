from typing import Dict, Type, Union, cast
from pyld.jsonld import JsonLdProcessor
from ...core.profile import Profile
from ..models import (
    CredentialBase,
    VerifiableCredentialBase,
    VerifiableCredentialBaseSchema,
    VerificationOptions,
    DIProof,
)
from ...wallet.key_type import ED25519, KeyType
from ..signatures.keys.wallet_key_pair import WalletKeyPair
from ..signatures import DataIntegrityProofException, DataIntegrityProof
from ..signatures.purposes.assertion_proof_purpose import AssertionProofPurpose
from ..signatures.cryptosuites.ed25519_signature_2020 import Ed25519Signature2020
from ..document_loader import DocumentLoader
from ..signatures.validation_result import DocumentVerificationResult
from ..signatures.cryptosuites import CRYPTOSUITES
import base64


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
        suite = CRYPTOSUITES[options.cryptosuite](
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=CRYPTOSUITES[vc.proof.cryptosuite]["key_type"],
            ).from_verification_method(vc.proof.verification_method)
        )
        verification = suite.verify_proof(vc.serialize())
        return verification

    async def verify_credential(
        self, vc: VerifiableCredentialBase, options: VerificationOptions
    ) -> DocumentVerificationResult:
        """Verify a Verifiable Credential."""

        if not vc.issuer_id:
            raise VerifierServiceError("VC issuer id is required")

        if not vc.credential_subject:
            raise VerifierServiceError("Credential subject is required")

        # validation_errors = VerifiableCredentialBaseSchema().validate(vc)
        # if len(validation_errors) > 0:
        #     raise DataIntegrityProofException(
        #         f"Unable to verify credential with invalid structure: {validation_errors}"
        #     )

        credential = vc.serialize().copy()
        proof = credential.pop("proof", None)

        verification_result = {
            "verified": False,
            "verifiedDocument": credential,
            "mediaType": None,
            "errors": [],
            "warnings": [],
        }

        if "credentialStatus" in credential:
            pass

        if "validFrom" in credential:
            pass

        if "validUntil" in credential:
            pass

        # if 'EnvelopedVerifiableCredential' in vc.type:
        #     credential_b64 = vc.id.split(';')[-1]
        #     credential = base64.urlsafe_b64decode(credential_b64.encode()).decode()

        if proof["type"] == "DataIntegrityProof":
            if "cryptosuite" not in proof:
                raise VerifierServiceError("Missing cryptosuite for DataIntegrityProof")
            suite = CRYPTOSUITES[proof['cryptosuite']]["suite"](
                document_loader=DocumentLoader(self.profile),
            )
            
            proof_verification = await suite.verify_proof(credential, proof)

            verification_result['verified'] = proof_verification['verified']
            if proof_verification['problem_detail']:
                verification_result['errors'].append(proof_verification['problem_detail'])
        # if proof["type"] in ["Ed25519Signature2020"]:
        #     suite = CRYPTOSUITES[proof["type"]]["suite"](
        #         key_pair=WalletKeyPair(
        #             profile=self.profile,
        #             key_type=CRYPTOSUITES[proof["type"]]["key_type"],
        #         ).from_verification_method(proof["verificationMethod"]),
        #         document_loader=DocumentLoader(self.profile),
        #     )

        #     verification = suite.verify_proof(credential, proof)
        # return verification
        return verification_result

        # raise VerifierServiceError(f"Invalid VC type")

        # try:

        #     # proof_set = JsonLdProcessor.get_values(vc, "proof")
        #     proof_set = [vc["proof"]] if isinstance(vc["proof"], dict) else vc["proof"]
        #     if len(proof_set) == 0:
        #         raise DataIntegrityProofException(
        #             "No matching proofs found in the given document"
        #         )
        #     proof_set = [{"@context": vc["@context"], **proof} for proof in proof_set]

        #     # if not purpose:
        #     purpose = AssertionProofPurpose()

        #     matches = [proof for proof in proof_set if purpose.match(proof)]

        #     if len(matches) == 0:
        #         return []

        #     results = []
        #     suites = [
        #         # Satisfy type checks with a cast to LinkedDataProof
        #         cast(
        #             DataIntegrityProof,
        #             # Instantiate suite with a key type
        #             SuiteClass(
        #                 key_pair=WalletKeyPair(profile=self.profile, key_type=key_type),
        #             ),
        #         )
        #         # for each suite class -> key_type pair from PROOF_KEY_TYPE_MAPPING
        #         for SuiteClass, key_type in PROOF_KEY_TYPE_MAPPING.items()
        #     ]
        #     for proof in matches:
        #         for suite in suites:
        #             if suite.match_proof(proof["type"]):
        #                 result = await suite.verify_proof(
        #                     proof=proof,
        #                     document=vc,
        #                     purpose=purpose,
        #                     document_loader=DocumentLoader(self.profile),
        #                 )
        #                 result.proof = proof
        #                 results.append(result)
        #                 errors.append(result.error)
        #     verified = True if len(errors) == 0 else False
        #     return DocumentVerificationResult(
        #         verified=verified, document=credential, errors=errors, warnings=warnings
        #     )
        # except Exception as e:
        #     errors.append(e)
        #     return DocumentVerificationResult(
        #         verified=False, document=credential, errors=errors, warnings=warnings
        #     )
