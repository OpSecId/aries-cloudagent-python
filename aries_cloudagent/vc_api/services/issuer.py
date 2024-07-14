"""Manager for performing Linked Data Proof signatures over JSON-LD formatted W3C VCs."""

import logging

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor

from ...core.profile import Profile
from ...wallet.base import BaseWallet
from ...wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ...wallet.did_info import DIDInfo
from ...wallet.jwt import jwt_sign
from ..resources.constants import SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL
from ..document_loader import DocumentLoader
from ..signatures.keys.wallet_key_pair import WalletKeyPair
from ..signatures.purposes.assertion_proof_purpose import AssertionProofPurpose
from ..models import CredentialBase, VerifiableCredentialBase, IssuanceOptions, DIProof
from datetime import datetime
from ..signatures.cryptosuites import CRYPTOSUITES


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

        if not credential.issuer_id:
            raise IssuerServiceError("Credential issuer id is required")

        if not credential.credential_subject:
            raise IssuerServiceError("Credential subject is required")

        options.verification_method = (
            options.verification_method
            if options.verification_method
            else await self.profile.context.inject(
                BaseVerificationKeyStrategy
            ).get_verification_method_id_for_did(
                credential.issuer_id, self.profile, proof_purpose="assertionMethod"
            )
        )

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

    async def _sign_vc_di(self, credential: CredentialBase, options: IssuanceOptions):
        """Sign a VC with Data Integrity."""
        # Ensure the Data Integrity context is included
        if SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL not in credential.context_urls:
            credential.add_context(SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL)

        # Get issuer information stored in the wallet
        async with self.profile.session() as session:
            did_info = await session.inject(BaseWallet).get_local_did(
                credential.issuer_id
            )

        # Instantiate cryptosuite class
        suite = CRYPTOSUITES[options.cryptosuite]["suite"](
            document_loader=DocumentLoader(self.profile),
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=CRYPTOSUITES[options.cryptosuite]["key_type"],
                public_key_base58=did_info.verkey,
            ),
        )

        # Create proof
        unsecured_document = credential.serialize()
        existing_proof = unsecured_document.pop("proof", None)
        """https://w3c.github.io/vc-data-integrity/#add-proof"""
        # TODO deal with parallel signatures
        proof = await suite.create_proof(
            unsecured_data_document=unsecured_document,
            proof_config={
                "@context": credential.context,
                "type": "DataIntegrityProof",
                # TODO convert timestamp offset
                "created": str(datetime.now().isoformat("T", "seconds")) + "Z",
                "cryptosuite": options.cryptosuite,
                "proofPurpose": "assertionMethod",
                "verificationMethod": options.verification_method,
            },
        )
        secured_data_document = unsecured_document.copy()
        secured_data_document["proof"] = proof

        return secured_data_document

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
