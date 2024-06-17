"""Services for performing Data Integrity Proof signatures over JSON-LD formatted W3C VCs."""

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor
from ..core.profile import Profile
from ..wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ..wallet.base import BaseWallet
from ..wallet.key_type import ED25519, KeyType
from ..storage.vc_holder.base import VCHolder
from .models import (
    CredentialV2Schema,
    VerifiableCredential,
    IssuanceOptions,
    DataIntegrityProof,
    VerifiablePresentation,
)
from .di_proofs.document_loader import DocumentLoader
from .di_proofs.constants import (
    SECURITY_CONTEXT_DATA_INTEGRITY_V2_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
)

from .di_proofs.keys.wallet_key_pair import WalletKeyPair
from .di_proofs import (
    CredentialIssuancePurpose,
    DataIntegrityProofException,
)
from .di_proofs.cryptosuites.ed25519_signature_2020 import Ed25519Signature2020
from .di_proofs.purposes.credential_issuance_purpose import CredentialIssuancePurpose

SignatureTypes = Union[Type[Ed25519Signature2020],]
SIGNATURE_SUITE_KEY_TYPE_MAPPING: Dict[SignatureTypes, KeyType] = {
    Ed25519Signature2020: ED25519,
}
PROOF_TYPE_SIGNATURE_SUITE_MAPPING: Dict[str, SignatureTypes] = {
    suite.signature_type: suite for suite in SIGNATURE_SUITE_KEY_TYPE_MAPPING
}


class VcApiServiceError(Exception):
    """Generic VcIssuerService Error."""


class VcApiService:
    """Class for managing Data Integrity Proof signatures over JSON-LD formatted W3C VCs."""

    def __init__(self, profile: Profile):
        """Initialize the VC LD Proof Manager."""
        self.profile = profile

    async def _get_suite_(self, did, verification_method):
        """Get signature suite for document"""

        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)

            did_info = await wallet.get_local_did(did)

        verkey_id_strategy = self.profile.context.inject(BaseVerificationKeyStrategy)
        verification_method = (
            verification_method
            or await verkey_id_strategy.get_verification_method_id_for_did(
                did, self.profile, proof_purpose="assertionMethod"
            )
        )

        proof_type = "ED25519Signature2020"
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]
        key_type = SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass]

        # SignatureClass = Ed25519Signature2020()
        suite = SignatureClass(
            verification_method=verification_method,
            proof=DataIntegrityProof(),
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=key_type,
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )
        return suite

    async def _sign_(self, document, suite):
        """Sign document"""

        signed_document = document.copy()
        document.pop("proof", None)
        proof_purpose = CredentialIssuancePurpose()
        document_loader = self.profile.inject(DocumentLoader)

        proof = await suite.create_proof(
            document=document, purpose=proof_purpose, document_loader=document_loader
        )

        JsonLdProcessor.add_value(signed_document, "proof", proof)
        return signed_document

    async def get_credential(self, credential_id: str) -> VerifiableCredential:
        """Get single stored VC."""
        holder = self.profile.context.inject(VCHolder)
        record = await holder.retrieve_credential_by_id(record_id=credential_id)
        return record

    async def get_credentials(self) -> List[VerifiableCredential]:
        """Get all stored VCs."""
        holder = self.profile.context.inject(VCHolder)
        search = holder.search_credentials()
        records = [record.serialize()["cred_value"] for record in await search.fetch()]
        return records

    async def issue_credential(
        self, credential: VerifiableCredential, options: IssuanceOptions
    ) -> VerifiableCredential:
        """Sign a VC with a Data Integrity Proof."""

        credential = VerifiableCredential.deserialize(credential)
        options = IssuanceOptions.deserialize(options)

        credential.add_context(SECURITY_CONTEXT_ED25519_2020_URL)
        credential.add_context(SECURITY_CONTEXT_DATA_INTEGRITY_V2_URL)

        # Validate credential
        errors = CredentialV2Schema().validate(credential)
        if len(errors) > 0:
            raise DataIntegrityProofException(
                f"Credential contains invalid structure: {errors}"
            )

        issuer_did = credential.issuer_id
        suite = self._get_suite_(issuer_did, options.verification_method)
        vc = self._sign_(credential, suite)

        return VerifiableCredential.deserialize(vc)

    async def verify_credential(
        self, vc: VerifiablePresentation, options: IssuanceOptions
    ) -> VerifiableCredential:
        """Sign a VC with a Data Integrity Proof."""

        vc = VerifiableCredential.deserialize(vc)
        options = IssuanceOptions.deserialize(options)

    async def store_credential(
        self, vc: VerifiablePresentation, options: IssuanceOptions
    ) -> VerifiableCredential:
        """Sign a VC with a Data Integrity Proof."""

        vc = VerifiableCredential.deserialize(vc)
        options = IssuanceOptions.deserialize(options)

    async def create_presentation(
        self, presentation: VerifiablePresentation, options: IssuanceOptions
    ) -> VerifiablePresentation:
        """Sign a VC with a Data Integrity Proof."""

        presentation = VerifiablePresentation.deserialize(presentation)
        options = IssuanceOptions.deserialize(options)

    async def verify_presentation(
        self, vp: VerifiablePresentation, options: IssuanceOptions
    ) -> VerifiableCredential:
        """Sign a VC with a Data Integrity Proof."""

        vp = VerifiablePresentation.deserialize(vp)
        options = IssuanceOptions.deserialize(options)
