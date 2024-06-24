"""Services for performing Data Integrity Proof signatures over JSON-LD formatted W3C VCs."""

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor
from . import StatusService
from ...core.profile import Profile
from ...wallet.default_verification_key_strategy import BaseVerificationKeyStrategy
from ...wallet.base import BaseWallet
from ...wallet.key_type import ED25519, KeyType
from ..models import (
    VerifiableCredentialSchemaV2,
    VerifiableCredentialV2,
    IssuanceOptions,
    DataIntegrityProof,
)
from ..proofs.constants import (
    SECURITY_CONTEXT_DATA_INTEGRITY_V2_URL,
    SECURITY_CONTEXT_ED25519_2020_URL,
)

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


class IssuerService:
    """VC-API Issuer service."""

    def __init__(self, profile: Profile):
        """Initialize the issuer service."""
        self.profile = profile

    async def _validate_(self, credential):
        errors = VerifiableCredentialSchemaV2().validate(credential)
        if len(errors) > 0:
            raise DataIntegrityProofException(
                f"Credential contains invalid structure: {errors}"
            )

    async def _get_suite_(
        self, did, verification_method=None, proof_type="Ed25519Signature2020"
    ):
        """Get signature suite"""

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
        
        SignatureClass = PROOF_TYPE_SIGNATURE_SUITE_MAPPING[proof_type]
        suite = SignatureClass(
            verification_method=verification_method,
            proof=DataIntegrityProof().serialize(),
            key_pair=WalletKeyPair(
                profile=self.profile,
                key_type=SIGNATURE_SUITE_KEY_TYPE_MAPPING[SignatureClass],
                public_key_base58=did_info.verkey if did_info else None,
            ),
        )
        return suite

    async def _sign_(self, document, suite):
        """Sign document"""

        document = document.serialize()
        signed_document = document.copy()
        document.pop("proof", None)
        proof_purpose = CredentialIssuancePurpose()

        proof = await suite.create_proof(document=document, purpose=proof_purpose)
        JsonLdProcessor.add_value(signed_document, "proof", proof)
        return signed_document

    async def issue_credential(
        self, credential: VerifiableCredentialV2, options: IssuanceOptions = {}
    ) -> VerifiableCredentialV2:
        """Sign a VC with a Data Integrity Proof."""
        # Validate credential
        await self._validate_(credential)
        
        if 'credentialStatus' in options and 'credentialStatus' not in credential:
            issuer = credential['issuer']['id'] if isinstance(credential['issuer'], dict) else credential['issuer']
            endpoint = 'https://admin.example.com/vc/credentials/status'
            status_entry = StatusService(self.profile).create_entry(issuer, options['credentialStatus'], endpoint)
            credential['credentialStatus'] = status_entry

        credential = VerifiableCredentialV2.deserialize(credential)
        options = IssuanceOptions.deserialize(options)

        credential.add_context(SECURITY_CONTEXT_DATA_INTEGRITY_V2_URL)
        credential.add_context(SECURITY_CONTEXT_ED25519_2020_URL)

        suite = await self._get_suite_(
            credential.issuer_id, options.verification_method
        )
        vc = await self._sign_(credential, suite)

        return vc