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
from ..di_proofs.keys.wallet_key_pair import WalletKeyPair
from ..di_proofs.purposes.assertion_proof_purpose import AssertionProofPurpose
from ..di_proofs.cryptosuites import CRYPTOSUITES
from ..models import CredentialBase, VerifiableCredentialBase, IssuanceOptions
from ..di_proofs.keys.wallet_key_pair import WalletKeyPair
from datetime import datetime, timezone

# from ..services import (
#     StatusService,
# )
from ..services.status import (
    StatusService,
)


class IssuerServiceError(Exception):
    """Generic Service Error."""


class IssuerService:
    """Class for issuing W3C VCs."""

    def __init__(self, profile: Profile):
        """Initialize the VC LD Proof Manager."""
        self.profile = profile

    async def issue_credential(
        self, credential: CredentialBase, options: IssuanceOptions
    ) -> VerifiableCredentialBase:
        """Prepare credential for issuance."""

        # Ensure the Credential has a issuer id
        if not credential.issuer_id:
            raise IssuerServiceError("Credential issuer id is required")

        # Derive the verification method from the options or the issuer id value
        options.verification_method = (
            options.verification_method
            if options.verification_method
            else await self.profile.context.inject(
                BaseVerificationKeyStrategy
            ).get_verification_method_id_for_did(
                credential.issuer_id, self.profile, proof_purpose="assertionMethod"
            )
        )

        # Ensure the Credential has at least 1 credential subject entry
        if not credential.credential_subject:
            raise IssuerServiceError("Credential subject is required")

        # Add status information if requested
        # Only supported for VCDM 2.0 w/ BitstringStatusList
        if options.credential_status:
            credential._credential_status = await StatusService(
                self.profile
            ).create_status_entry(options.credential_status["statusPurpose"])

        # Ensure a verification method is available
        if not options.verification_method:
            raise IssuerServiceError(
                "Unable to get retrieve verification method for did"
            )

        securing_mechanism = (
            options.securing_mechanism
            if options.securing_mechanism
            else self.profile.settings.get("w3c_vc.securing_mechanism")
        )

        if securing_mechanism == "vc-di":
            return await self._sign_vc_di(credential, options)

        elif securing_mechanism == "vc-jose":
            return await self._sign_vc_jose(credential, options)

        raise IssuerServiceError(f"Invalid securing mechanism {securing_mechanism}")

    async def add_proof(self, document, options):
        did = options['verificationMethod'].split('#')[0]

        # Get issuer information stored in the wallet
        async with self.profile.session() as session:
            did_info = await session.inject(BaseWallet).get_local_did(did)
            
        suite = CRYPTOSUITES[options['cryptosuite']](
            profile=self.profile,
            verkey=did_info.verkey,
        )
        signed_document = await suite.add_proof(
            unsecured_data_document=document, proof_config=options
        )

        return signed_document

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

        proof_config = proof_config | {
            "verificationMethod": options.verification_method,
            "proofPurpose": "assertionMethod",
            # Create timestamp
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

        try:
            suite = CRYPTOSUITES[suite_label](
                profile=self.profile,
                verkey=did_info.verkey,
            )
        except:
            raise IssuerServiceError("Invalid cryptosuite")

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
