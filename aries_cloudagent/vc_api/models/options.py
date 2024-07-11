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
        verification_method: Optional[str] = None,
    ) -> None:
        """Initialize the IssuanceOptions instance."""

        self.verification_method = verification_method

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, IssuanceOptions):
            return self.verification_method == o.verification_method

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

    proof_type = fields.Str(
        data_key="proofType",
        required=False,
        metadata={
            "description": (
                "The proof type used for the proof. Should match suites registered in"
                " the Linked Data Cryptographic Suite Registry"
            ),
            "example": "Ed25519Signature2018",
        },
    )

    proof_purpose = fields.Str(
        data_key="proofPurpose",
        required=False,
        metadata={
            "description": (
                "The proof purpose used for the proof. Should match proof purposes"
                " registered in the Linked Data Proofs Specification"
            ),
            "example": "assertionMethod",
        },
    )

    created = fields.Str(
        required=False,
        validate=INDY_ISO8601_DATETIME_VALIDATE,
        metadata={
            "description": (
                "The date and time of the proof (with a maximum accuracy in seconds)."
                " Defaults to current system time"
            ),
            "example": INDY_ISO8601_DATETIME_EXAMPLE,
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

    # credential_status = fields.Nested(
    #     CredentialStatusOptionsSchema(),
    #     data_key="credentialStatus",
    #     required=False,
    #     metadata={
    #         "description": (
    #             "The credential status mechanism to use for the credential. Omitting"
    #             " the property indicates the issued credential will not include a"
    #             " credential status"
    #         )
    #     },
    # )


class VerificationOptionsSchema(BaseModelSchema):
    """Credential verification options schema."""

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = VerificationOptions
