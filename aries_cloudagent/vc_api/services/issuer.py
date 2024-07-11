"""Manager for performing Linked Data Proof signatures over JSON-LD formatted W3C VCs."""

import logging

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor

from ...core.profile import Profile
from ...wallet.base import BaseWallet
from ...wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ...wallet.did_info import DIDInfo
from ...wallet.error import WalletNotFoundError
from ...wallet.key_type import ED25519, KeyType
from ..resources.constants import (
    DATA_INTEGRITY_V2_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
)
from ..document_loader import DocumentLoader
from ..crypto.keys.wallet_key_pair import WalletKeyPair
from ..crypto.purposes.assertion_proof_purpose import AssertionProofPurpose
from ..crypto.suites.ed25519_signature_2020 import Ed25519Signature2020
from ..models import (
    IssuanceOptions,
    DIProof,
    Credential_V1,
    Credential_V2,
    VerifiableCredential_V1,
    VerifiableCredential_V2,
)

SignatureTypes = Union[
    Type[Ed25519Signature2020],
]
ProofTypes = Union[
    Type[Ed25519Signature2020],
]
SIGNATURE_SUITE_KEY_TYPE_MAPPING: Dict[SignatureTypes, KeyType] = {
    Ed25519Signature2020: ED25519,
}
PROOF_KEY_TYPE_MAPPING = cast(
    Dict[ProofTypes, KeyType], SIGNATURE_SUITE_KEY_TYPE_MAPPING
)


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


class IssuerServiceError(Exception):
    """Generic Service Error."""

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


    async def assert_can_issue_with_id_and_proof_type(
        self, issuer_id: Optional[str], proof_type: Optional[str]
    ):
        """Assert that it is possible to issue using the specified id and proof type.

        Args:
            issuer_id (str): The issuer id
            proof_type (str): the signature suite proof type

        Raises:
            IssuerServiceError:
                - If the proof type is not supported
                - If the issuer id is not a did
                - If the did is not found in th wallet
                - If the did does not support to create signatures for the proof type

        """
        if not issuer_id or not proof_type:
            raise IssuerServiceError(
                "Issuer id and proof type are required to issue a credential."
            )

        try:
            # Check if it is a proof type we can issue with
            if proof_type not in PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys():
                raise IssuerServiceError(
                    f"Unable to sign credential with unsupported proof type {proof_type}."
                    f" Supported proof types: {PROOF_TYPE_SIGNATURE_SUITE_MAPPING.keys()}"
                )

            if not issuer_id.startswith("did:"):
                raise IssuerServiceError(
                    f"Unable to issue credential with issuer id: {issuer_id}."
                    " Only issuance with DIDs is supported"
                )

            # Retrieve did from wallet. Will throw if not found
            did = await self._did_info_for_did(issuer_id)

            # Raise error if we cannot issue a credential with this proof type
            # using this DID from
            did_proof_types = KEY_TYPE_SIGNATURE_TYPE_MAPPING[did.key_type]
            if proof_type not in did_proof_types:
                raise IssuerServiceError(
                    f"Unable to issue credential with issuer id {issuer_id} and proof "
                    f"type {proof_type}. DID only supports proof types {did_proof_types}"
                )

        except WalletNotFoundError:
            raise IssuerServiceError(
                f"Issuer did {issuer_id} not found."
                " Unable to issue credential with this DID."
            )

    async def issue(
        self, credential: Union[Credential_V1, Credential_V2], options: IssuanceOptions
    ) -> Union[VerifiableCredential_V1, VerifiableCredential_V2]:
        """Sign a VC with a Data Integrity Proof."""

        if DATA_INTEGRITY_V2_URL not in credential.context_urls:
            credential.add_context(DATA_INTEGRITY_V2_URL)

        if SECURITY_CONTEXT_ED25519_2020_URL not in credential.context_urls:
            credential.add_context(SECURITY_CONTEXT_ED25519_2020_URL)

        if not credential.credential_subject:
            raise IssuerServiceError("Credential subject is required")

        # Get signature suite, proof purpose and document loader

        issuer_id = credential.issuer_id

        if not issuer_id:
            raise IssuerServiceError("Credential issuer id is required")

        if not issuer_id.startswith("did:"):
            raise IssuerServiceError(
                f"Unable to issue credential with issuer id: {issuer_id}."
                " Only issuance with DIDs is supported"
            )

        try:
            did_info = await self._did_info_for_did(issuer_id)
        except WalletNotFoundError:
            raise IssuerServiceError(
                f"Issuer did {issuer_id} not found."
                " Unable to issue credential with this DID."
            )

        verkey_id_strategy = self.profile.context.inject(BaseVerificationKeyStrategy)
        verification_method = (
            options.verification_method
            or await verkey_id_strategy.get_verification_method_id_for_did(
                issuer_id, self.profile, proof_purpose="assertionMethod"
            )
        )

        if verification_method is None:
            raise IssuerServiceError(
                f"Unable to get retrieve verification method for did {issuer_id}"
            )

        # Get signature class based on proof type
        proof_type = "Ed25519Signature2020"
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]

        # Generically create signature class
        suite = SignatureClass(
            verification_method=verification_method,
            proof=DIProof().serialize(),
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass],
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )

        # Default proof purpose is assertionMethod
        proof_purpose = AssertionProofPurpose()

        credential = credential.serialize()
        # errors = CredentialSchema_V1().validate(credential)
        # if len(errors) > 0:
        #     raise DataIntegrityProofException(
        #         f"Credential contains invalid structure: {errors}"
        #     )

        # Set default proof purpose if not set

        vc = credential.copy()
        existing_proof = credential.pop("proof", None)

        # document_loader = self.profile.inject(DocumentLoader)
        document_loader = DocumentLoader(self.profile)
        proof = await suite.create_proof(
            document=credential, purpose=proof_purpose, document_loader=document_loader
        )

        JsonLdProcessor.add_value(vc, "proof", proof)

        return vc
