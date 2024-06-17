"""Options for specifying how the linked data proof is created."""

from typing import Optional

from marshmallow import INCLUDE, Schema, fields

from aries_cloudagent.messaging.valid import (
    UUID4_EXAMPLE,
)

from ...messaging.models.base import BaseModel, BaseModelSchema


class IssuanceOptions(BaseModel):
    """VC issuance options model."""

    class Meta:
        """IssuanceOptions metadata."""

        schema_class = "IssuanceOptionsSchema"

    def __init__(
        self,
        verification_method: Optional[str] = None,
        domain: Optional[str] = None,
        challenge: Optional[str] = None,
        credential_status: Optional[dict] = None,
    ) -> None:
        """Initialize the IssuanceOptions instance."""

        self.verification_method = verification_method
        self.domain = domain
        self.challenge = challenge
        self.credential_status = credential_status

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, IssuanceOptions):
            return (
                self.domain == o.domain
                and self.challenge == o.challenge
                and self.credential_status == o.credential_status
            )

        return False


class CredentialStatusOptionsSchema(Schema):
    """Linked data proof credential status options schema."""

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE

    type = fields.Str(
        required=True,
        metadata={
            "description": (
                "Credential status method type to use for the credential. Should match"
                " status method registered in the Verifiable Credential Extension"
                " Registry"
            ),
            "example": "CredentialStatusList2017",
        },
    )


class IssuanceOptionsSchema(BaseModelSchema):
    """Linked data proof verifiable credential options schema."""

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = IssuanceOptions

    verification_method = fields.Str(
        data_key="verificationMethod",
        required=False,
        metadata={
            "description": (
                "The verification method to use for the proof. Should match a"
                " verification method in the wallet"
            ),
            "example": "did:example:123456#key-1",
        },
    )

    domain = fields.Str(
        required=False,
        metadata={
            "description": "The intended domain of validity for the proof",
            "example": "example.com",
        },
    )

    challenge = fields.Str(
        required=False,
        metadata={
            "description": (
                "A challenge to include in the proof. SHOULD be provided by the"
                " requesting party of the credential (=holder)"
            ),
            "example": UUID4_EXAMPLE,
        },
    )

    credential_status = fields.Nested(
        CredentialStatusOptionsSchema(),
        data_key="credentialStatus",
        required=False,
        metadata={
            "description": (
                "The credential status mechanism to use for the credential. Omitting"
                " the property indicates the issued credential will not include a"
                " credential status"
            )
        },
    )
