"""Services for performing Data Integrity Proof signatures over JSON-LD formatted W3C VCs."""

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor
from ...core.profile import Profile
from ...wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ...wallet.base import BaseWallet
from ...wallet.key_type import ED25519, KeyType
from ...storage.vc_holder.base import VCHolder
from ...storage.vc_holder.vc_record import VCRecord
from ..models import (
    CredentialSchema,
    VerifiableCredential,
    IssuanceOptions,
    DataIntegrityProof,
    VerifiablePresentation,
)
from ..proofs.constants import (
    SECURITY_CONTEXT_DATA_INTEGRITY_V2_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
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


class HolderService:
    """VC-API Holder service."""

    def __init__(self, profile: Profile):
        """Initialize the verifier service."""
        self.profile = profile

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

    async def create_presentation(
        self, presentation: VerifiablePresentation, options: IssuanceOptions
    ) -> VerifiablePresentation:
        """Sign a VC with a Data Integrity Proof."""

        presentation = VerifiablePresentation.deserialize(presentation)
        options = IssuanceOptions.deserialize(options)

    async def store_credential(
        self, vc: VerifiablePresentation, options: IssuanceOptions
    ) -> VerifiableCredential:
        """Store a verifiable credential."""

        # Saving expanded type as a cred_tag
        document_loader = self.profile.inject(DocumentLoader)
        expanded = jsonld.expand(
            vc.serialize(), options={"documentLoader": document_loader}
        )
        types = JsonLdProcessor.get_values(
            expanded[0],
            "@type",
        )
        vc_record = VCRecord(
            contexts=vc.context_urls,
            expanded_types=types,
            issuer_id=vc.issuer_id,
            subject_ids=vc.credential_subject_ids,
            schema_ids=[],  # Schemas not supported yet
            proof_types=[vc.proof.type],
            cred_value=vc.serialize(),
            given_id=vc.id,
            record_id=cred_id,
            cred_tags=None,  # Tags should be derived from credential values
        )

        async with self.profile.session() as session:
            vc_holder = session.inject(VCHolder)

            await vc_holder.store_credential(vc_record)

