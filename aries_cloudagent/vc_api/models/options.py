"""Options for specifying how the linked data proof is created."""

from typing import Optional

from marshmallow import INCLUDE, Schema, fields

from aries_cloudagent.messaging.valid import (
    INDY_ISO8601_DATETIME_EXAMPLE,
    INDY_ISO8601_DATETIME_VALIDATE,
    UUID4_EXAMPLE,
)

from ...messaging.models.base import BaseModel, BaseModelSchema


class IssuanceOptions(BaseModel):
    """Verifiable credential issuance options model."""

    class Meta:
        """IssuanceOptions metadata."""

        schema_class = "IssuanceOptionsSchema"

    def __init__(
        self,
        proof_type: Optional[str] = None,
        verification_method: Optional[str] = None
    ) -> None:
        """Initialize the IssuanceOptions instance."""

        self.proof_type = proof_type
        self.verification_method = verification_method

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, IssuanceOptions):
            return (
                self.proof_type == o.proof_type
                and self.verification_method == o.verification_method
            )

        return False

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

    proof_type = fields.Str(
        data_key="proofType",
        required=False,
        metadata={
            "description": (
                "The proof type used for the proof. Should match suites registered in"
                " the Linked Data Cryptographic Suite Registry"
            ),
            "example": "Ed25519Signature2020",
        },
    )
