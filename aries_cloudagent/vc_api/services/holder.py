"""Manager for performing Linked Data Proof signatures over JSON-LD formatted W3C VCs."""

import logging

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor

from ...core.profile import Profile
from ...wallet.base import BaseWallet
from ...wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ...wallet.jwt import jwt_sign
from ..resources.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
)
from ..document_loader import DocumentLoader
from ..crypto.keys.wallet_key_pair import WalletKeyPair
from ..crypto.purposes.assertion_proof_purpose import AssertionProofPurpose
from ..models import CredentialBase, VerifiableCredentialBase, IssuanceOptions, PresentationBase
from datetime import datetime, timezone
from ..crypto.suites import CRYPTOSUITES

# from ..services import (
#     StatusService,
# )
from ..services.status import (
    StatusService,
)


class HolderServiceError(Exception):
    """Generic Service Error."""


class HolderService:
    """Class for issuing W3C VCs."""

    def __init__(self, profile: Profile):
        """Initialize the VC LD Proof Manager."""
        self.profile = profile

    async def create_presentations(
        self, presentation: PresentationBase, options: IssuanceOptions
    ) -> PresentationBase:
        """Prepare credential for issuance."""

        # Ensure the Credential has a issuer id
        if not presentation.holder_id:
            raise HolderServiceError("Presentation holder id is required")

        # Derive the verification method from the options or the issuer id value
        options.verification_method = (
            options.verification_method
            if options.verification_method
            else await self.profile.context.inject(
                BaseVerificationKeyStrategy
            ).get_verification_method_id_for_did(
                presentation.holder_id, self.profile, proof_purpose="assertionMethod"
            )
        )

        # Ensure a verification method is available
        if not options.verification_method:
            raise HolderServiceError(
                "Unable to get retrieve verification method for did"
            )

        securing_mechanism = (
            options.securing_mechanism
            if options.securing_mechanism
            else self.profile.settings.get("w3c_vc.securing_mechanism")
        )

        if securing_mechanism == "vc-di":
            return await self._sign_vc_di(presentation, options)

        elif securing_mechanism == "vc-jose":
            return await self._sign_vc_jose(presentation, options)

        raise HolderServiceError(f"Invalid securing mechanism {securing_mechanism}")

    async def _sign_vc_di(self, credential: CredentialBase, options: IssuanceOptions):
        """Sign a VC with Data Integrity."""

        proof_config = {}

        # Default to DataIntegrityProof if no specific proof type is given
        proof_config["type"] = options.type if options.type else "DataIntegrityProof"

        # Get default cryptosuite is none provided
        proof_config["cryptosuite"] = (
            options.cryptosuite
            if options.cryptosuite
            else self.profile.settings.get("w3c_vc.di_cryptosuite")
        )

        # Create timestamp
        proof_config = proof_config | {
            "verificationMethod": options.verification_method,
            "proofPurpose": "assertionMethod",
            "created": str(datetime.now(timezone.utc).isoformat("T", "seconds")),
        }

        # Get issuer information stored in the wallet
        async with self.profile.session() as session:
            did_info = await session.inject(BaseWallet).get_local_did(
                credential.issuer_id
            )

        # Instantiate cryptosuite class
        if proof_config["type"] == "DataIntegrityProof":
            suite_label = proof_config["cryptosuite"]

        # Include typed suites
        elif options.type in ["Ed25519Signature2020"]:
            proof_config.pop("cryptosuite")
            suite_label = options.type
            
        try:
            suite = CRYPTOSUITES[suite_label]["suite"](
                document_loader=DocumentLoader(self.profile),
                key_pair=WalletKeyPair(
                    profile=self.profile,
                    key_type=CRYPTOSUITES[suite_label]["key_type"],
                    public_key_base58=did_info.verkey,
                ),
            )
        except:
            raise HolderServiceError('Invalid cryptosuite')

        # Create proof
        unsecured_data_document = credential.serialize()

        # TODO deal with parallel signatures
        existing_proof = unsecured_data_document.pop("proof", None)

        """https://w3c.github.io/vc-data-integrity/#add-proof"""
        vc = await suite.add_proof(
            unsecured_data_document=unsecured_data_document, proof_config=proof_config
        )

        return vc

    async def _sign_vc_jose(self, credential: CredentialBase, options: IssuanceOptions):
        """Sign a VC with VC-JOSE."""
        vc_jwt = await jwt_sign(
            self.profile,
            {"typ": "vc-ld+jwt", "cty": "vc", "alg": "HS256"},
            credential.serialize(),
            credential.issuer_id,
            options.verification_method,
        )
        return {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
            ],
            "type": ["EnvelopedVerifiableCredential"],
            "id": f"data:application/vc+jwt;{vc_jwt}",
        }
