"""Manager for performing Linked Data Proof signatures over JSON-LD formatted W3C VCs."""
import logging

from typing import Dict, List, Optional, Type, Union, cast

from pyld import jsonld
from pyld.jsonld import JsonLdProcessor

from ...core.profile import Profile
from ...storage.vc_holder.base import VCHolder
from ...storage.vc_holder.vc_record import VCRecord
from ...wallet.base import BaseWallet
from ...wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ...wallet.did_info import DIDInfo
from ...wallet.error import WalletNotFoundError
from ...wallet.key_type import BLS12381G2, ED25519, KeyType
from ..constants import (
    SECURITY_CONTEXT_BBS_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
)
from ..signatures.crypto.wallet_key_pair import WalletKeyPair
from ..document_loader import DocumentLoader
from ..signatures.purposes.authentication_proof_purpose import AuthenticationProofPurpose
from ..signatures.purposes.credential_issuance_purpose import CredentialIssuancePurpose
from ..signatures.purposes.proof_purpose import ProofPurpose
from ..signatures.suites.bbs_bls_signature_2020 import BbsBlsSignature2020
from ..signatures.suites.bbs_bls_signature_proof_2020 import BbsBlsSignatureProof2020
from ..signatures.suites.ed25519_signature_2018 import Ed25519Signature2018
from ..signatures.suites.ed25519_signature_2020 import Ed25519Signature2020
from ..signatures.suites.linked_data_proof import LinkedDataProof
from ..signatures.validation_result import DocumentVerificationResult
from ..signatures import ProofSet
# from ..vc_ld.models.presentation import VerifiablePresentation
# from ..vc_ld.validation_result import PresentationVerificationResult
from ..signatures.external_suite import ExternalSuiteNotFoundError, ExternalSuiteProvider
from ..error import ServiceError, DataIntegrityProofException
from ..models import IssuanceOptions, DIProof, CredentialSchema_V1, CredentialSchema_V2, Credential_V1, Credential_V2, VerifiableCredential_V1, VerifiableCredential_V2
# from .prove import sign_presentation
# from .verify import verify_credential, verify_presentation

SignatureTypes = Union[
    Type[Ed25519Signature2018],
    Type[Ed25519Signature2020],
    Type[BbsBlsSignature2020],
]
ProofTypes = Union[
    Type[Ed25519Signature2018],
    Type[Ed25519Signature2020],
    Type[BbsBlsSignature2020],
    Type[BbsBlsSignatureProof2020],
]
SUPPORTED_ISSUANCE_PROOF_PURPOSES = {
    CredentialIssuancePurpose.term,
    AuthenticationProofPurpose.term,
}
SIGNATURE_SUITE_KEY_TYPE_MAPPING: Dict[SignatureTypes, KeyType] = {
    Ed25519Signature2018: ED25519,
    Ed25519Signature2020: ED25519,
}
PROOF_KEY_TYPE_MAPPING = cast(
    Dict[ProofTypes, KeyType], SIGNATURE_SUITE_KEY_TYPE_MAPPING
)


# We only want to add bbs suites to supported if the module is installed
if BbsBlsSignature2020.BBS_SUPPORTED:
    SIGNATURE_SUITE_KEY_TYPE_MAPPING[BbsBlsSignature2020] = BLS12381G2
    PROOF_KEY_TYPE_MAPPING[BbsBlsSignatureProof2020] = BLS12381G2


PROOF_TYPE_SIGNATURE_SUITE_MAPPING: Dict[str, SignatureTypes] = {
    suite.signature_type: suite for suite in SIGNATURE_SUITE_KEY_TYPE_MAPPING
}


# key_type -> set of signature types mappings
KEY_TYPE_SIGNATURE_TYPE_MAPPING = {
    key_type: {
        suite.signature_type
        for suite, kt in SIGNATURE_SUITE_KEY_TYPE_MAPPING.items()
        if kt == key_type
    }
    for key_type in SIGNATURE_SUITE_KEY_TYPE_MAPPING.values()
}


class IssuerService:
    """Class for managing Linked Data Proof signatures over JSON-LD formatted W3C VCs."""

    def __init__(self, profile: Profile):
        """Initialize the VC LD Proof Manager."""
        self.profile = profile

    async def _did_info_for_did(self, did: str) -> DIDInfo:
        """Get the did info for specified did.

        If the did starts with did:sov it will remove the prefix for
        backwards compatibility with not fully qualified did.

        Args:
            did (str): The did to retrieve from the wallet.

        Raises:
            WalletNotFoundError: If the did is not found in the wallet.

        Returns:
            DIDInfo: did information

        """
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)

            # If the did starts with did:sov we need to query without
            if did.startswith("did:sov:"):
                return await wallet.get_local_did(did.replace("did:sov:", ""))

            # All other methods we can just query
            return await wallet.get_local_did(did)

    async def _get_suite_for_document(
        self,
        document: Union[VerifiableCredential_V1],
        options: IssuanceOptions,
    ) -> LinkedDataProof:
        issuer_id = document.issuer_id

        proof_type = options.proof_type

        if not issuer_id:
            raise ServiceError("Credential issuer id is required")

        if not proof_type:
            raise ServiceError("Proof type is required")

        # Assert we can issue the credential based on issuer + proof_type
        if not issuer_id or not proof_type:
            raise ServiceError(
                "Issuer id and proof type are required to issue a credential."
            )

        try:
            # Check if it is a proof type we can issue with
            if proof_type not in PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys():
                raise ServiceError(
                    f"Unable to sign credential with unsupported proof type {proof_type}."
                    f" Supported proof types: {PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys()}"
                )

            if not issuer_id.startswith("did:"):
                raise ServiceError(
                    f"Unable to issue credential with issuer id: {issuer_id}."
                    " Only issuance with DIDs is supported"
                )

            # Retrieve did from wallet. Will throw if not found
            did = await self._did_info_for_did(issuer_id)

            # Raise error if we cannot issue a credential with this proof type
            # using this DID from
            did_proof_types = KEY_TYPE_SIGNATURE_TYPE_MAPPING[did.key_type]
            if proof_type not in did_proof_types:
                raise ServiceError(
                    f"Unable to issue credential with issuer id {issuer_id} and proof "
                    f"type {proof_type}. DID only supports proof types {did_proof_types}"
                )

        except WalletNotFoundError:
            raise ServiceError(
                f"Issuer did {issuer_id} not found."
                " Unable to issue credential with this DID."
            )

        # Create base proof object with options
        proof = DIProof(
            created=options.created,
            domain=options.domain,
            challenge=options.challenge,
        )

        did_info = await self._did_info_for_did(issuer_id)
        verkey_id_strategy = self.profile.context.inject(BaseVerificationKeyStrategy)
        verification_method = (
            options.verification_method
            or await verkey_id_strategy.get_verification_method_id_for_did(
                issuer_id, self.profile, proof_purpose="assertionMethod"
            )
        )

        if verification_method is None:
            raise ServiceError(
                f"Unable to get retrieve verification method for did {issuer_id}"
            )
            
        proof=proof.serialize()

        try:
            if (provider := self.profile.inject_or(ExternalSuiteProvider)) and (
                suite := await provider.get_suite(
                    self.profile, proof_type, proof, verification_method, did_info
                )
            ):
                return suite
        except ExternalSuiteNotFoundError as error:
            raise ServiceError(
                f"Unable to get signature suite for proof type {proof_type} "
                "using external provider."
            ) from error

        # Get signature class based on proof type
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]

        # Generically create signature class
        suite = SignatureClass(
            verification_method=verification_method,
            proof=proof,
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass],
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )

        return suite

    async def assert_can_issue_with_id_and_proof_type(
        self, issuer_id: Optional[str], proof_type: Optional[str]
    ):
        """Assert that it is possible to issue using the specified id and proof type.

        Args:
            issuer_id (str): The issuer id
            proof_type (str): the signature suite proof type

        Raises:
            ServiceError:
                - If the proof type is not supported
                - If the issuer id is not a did
                - If the did is not found in th wallet
                - If the did does not support to create signatures for the proof type

        """
        if not issuer_id or not proof_type:
            raise ServiceError(
                "Issuer id and proof type are required to issue a credential."
            )

        try:
            # Check if it is a proof type we can issue with
            if proof_type not in PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys():
                raise ServiceError(
                    f"Unable to sign credential with unsupported proof type {proof_type}."
                    f" Supported proof types: {PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys()}"
                )

            if not issuer_id.startswith("did:"):
                raise ServiceError(
                    f"Unable to issue credential with issuer id: {issuer_id}."
                    " Only issuance with DIDs is supported"
                )

            # Retrieve did from wallet. Will throw if not found
            did = await self._did_info_for_did(issuer_id)

            # Raise error if we cannot issue a credential with this proof type
            # using this DID from
            did_proof_types = KEY_TYPE_SIGNATURE_TYPE_MAPPING[did.key_type]
            if proof_type not in did_proof_types:
                raise ServiceError(
                    f"Unable to issue credential with issuer id {issuer_id} and proof "
                    f"type {proof_type}. DID only supports proof types {did_proof_types}"
                )

        except WalletNotFoundError:
            raise ServiceError(
                f"Issuer did {issuer_id} not found."
                " Unable to issue credential with this DID."
            )


    async def issue(
        self, credential: Union[Credential_V1, Credential_V2], options: IssuanceOptions
    ) -> Union[VerifiableCredential_V1, VerifiableCredential_V2]:
        """Sign a VC with a Data Integrity Proof."""
        if SECURITY_CONTEXT_ED25519_2020_URL not in credential.context_urls:
            credential.add_context(SECURITY_CONTEXT_ED25519_2020_URL)
            
        subject = credential.credential_subject
        if isinstance(subject, list):
            subject = subject[0]

        if not subject:
            raise ServiceError("Credential subject is required")
        
        # Get signature suite, proof purpose and document loader
        
        issuer_id = credential.issuer_id
        proof_type = options.proof_type

        if not issuer_id:
            raise ServiceError("Credential issuer id is required")

        if not proof_type:
            raise ServiceError("Proof type is required")

        # Assert we can issue the credential based on issuer + proof_type
        if not issuer_id or not proof_type:
            raise ServiceError(
                "Issuer id and proof type are required to issue a credential."
            )

        try:
            # Check if it is a proof type we can issue with
            if proof_type not in PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys():
                raise ServiceError(
                    f"Unable to sign credential with unsupported proof type {proof_type}."
                    f" Supported proof types: {PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys()}"
                )

            if not issuer_id.startswith("did:"):
                raise ServiceError(
                    f"Unable to issue credential with issuer id: {issuer_id}."
                    " Only issuance with DIDs is supported"
                )

            # Retrieve did from wallet. Will throw if not found
            did_info = await self._did_info_for_did(issuer_id)

            # Raise error if we cannot issue a credential with this proof type
            # using this DID from
            did_proof_types = KEY_TYPE_SIGNATURE_TYPE_MAPPING[did_info.key_type]
            if proof_type not in did_proof_types:
                raise ServiceError(
                    f"Unable to issue credential with issuer id {issuer_id} and proof "
                    f"type {proof_type}. DID only supports proof types {did_proof_types}"
                )

        except WalletNotFoundError:
            raise ServiceError(
                f"Issuer did {issuer_id} not found."
                " Unable to issue credential with this DID."
            )

        # Create base proof object with options
        proof = DIProof(
            created=options.created,
            domain=options.domain,
            challenge=options.challenge,
        )

        verkey_id_strategy = self.profile.context.inject(BaseVerificationKeyStrategy)
        verification_method = (
            options.verification_method
            or await verkey_id_strategy.get_verification_method_id_for_did(
                issuer_id, self.profile, proof_purpose="assertionMethod"
            )
        )

        if verification_method is None:
            raise ServiceError(
                f"Unable to get retrieve verification method for did {issuer_id}"
            )
            
        proof=proof.serialize()

        try:
            if (provider := self.profile.inject_or(ExternalSuiteProvider)) and (
                suite := await provider.get_suite(
                    self.profile, proof_type, proof, verification_method, did_info
                )
            ):
                return suite
        except ExternalSuiteNotFoundError as error:
            raise ServiceError(
                f"Unable to get signature suite for proof type {proof_type} "
                "using external provider."
            ) from error

        # Get signature class based on proof type
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]

        # Generically create signature class
        suite = SignatureClass(
            verification_method=verification_method,
            proof=proof,
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass],
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )      
        

        # Default proof purpose is assertionMethod
        proof_purpose = options.proof_purpose or CredentialIssuancePurpose.term

        if proof_purpose == CredentialIssuancePurpose.term:
            proof_purpose = CredentialIssuancePurpose()
        elif proof_purpose == AuthenticationProofPurpose.term:
            # assert challenge is present for authentication proof purpose
            if not options.challenge:
                raise ServiceError(
                    f"Challenge is required for '{proof_purpose}' proof purpose."
                )

            proof_purpose = AuthenticationProofPurpose(challenge=options.challenge, domain=options.domain)
        else:
            raise ServiceError(
                f"Unsupported proof purpose: {proof_purpose}. "
                f"Supported proof types are: {SUPPORTED_ISSUANCE_PROOF_PURPOSES}"
            )
            
        

        credential = credential.serialize()
        # errors = CredentialSchema_V1().validate(credential)
        # if len(errors) > 0:
        #     raise DataIntegrityProofException(
        #         f"Credential contains invalid structure: {errors}"
        #     )

        # Set default proof purpose if not set
        if not proof_purpose:
            proof_purpose = CredentialIssuancePurpose()
        
        vc = credential.copy()
        credential.pop("proof", None)

        # document_loader = self.profile.inject(DocumentLoader)
        document_loader = DocumentLoader(self.profile)
        
        # create the new proof, suites MUST output a proof using security-v2 `@context`
        proof = await suite.create_proof(
            document=credential, purpose=proof_purpose, document_loader=document_loader
        )
        
        JsonLdProcessor.add_value(vc, "proof", proof)

        return vc
