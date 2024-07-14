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
    """Credential issuance options model."""

    class Meta:
        """IssuanceOptions metadata."""

        schema_class = "IssuanceOptionsSchema"

    def __init__(
        self,
        cryptosuite: Optional[str] = None,
        securing_mechanism: Optional[str] = None,
        verification_method: Optional[str] = None,
    ) -> None:
        """Initialize the IssuanceOptions instance."""

        self.cryptosuite = cryptosuite
        self.securing_mechanism = securing_mechanism
        self.verification_method = verification_method

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, IssuanceOptions):
            return (
                self.verification_method == o.verification_method
                and self.securing_mechanism == o.securing_mechanism
                and self.cryptosuite == o.cryptosuite
            )

        return False


class VerificationOptions(BaseModel):
    """Credential verification options model."""

    class Meta:
        """VerificationOptions metadata."""

        schema_class = "VerificationOptionsSchema"

    def __init__(
        self,
    ) -> None:
        """Initialize the VerificationOptions instance."""

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, VerificationOptions):
            return ()

        return False


# class CredentialStatusOptionsSchema(Schema):
#     """Linked data proof credential status options schema."""

#     class Meta:
#         """Accept parameter overload."""

#         unknown = INCLUDE

#     type = fields.Str(
#         required=True,
#         metadata={
#             "description": (
#                 "Credential status method type to use for the credential. Should match"
#                 " status method registered in the Verifiable Credential Extension"
#                 " Registry"
#             ),
#             "example": "CredentialStatusList2017",
#         },
#     )


class IssuanceOptionsSchema(BaseModelSchema):
    """Credential issuance options schema."""

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

    securing_mechanism = fields.Str(
        data_key="securingMechanism",
        required=False,
        metadata={
            "description": ("The securing mechanism used for the proof."),
            "example": "vc-data-integrity",
        },
    )

    cryptosuite = fields.Str(
        data_key="cryptosuite",
        required=False,
        metadata={
            "description": (
                "The cryptosuite used for the proof. Should match suites registered in"
                " the Data Integrity Specification"
            ),
            "example": "Ed25519Signature2020",
        },
    )


class VerificationOptionsSchema(BaseModelSchema):
    """Credential verification options schema."""

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = VerificationOptions
