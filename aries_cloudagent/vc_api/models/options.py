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
        type: Optional[str] = None,
        cryptosuite: Optional[str] = None,
        securing_mechanism: Optional[str] = None,
        verification_method: Optional[str] = None,
        credential_id: Optional[str] = None,
        credential_status: Optional[dict] = None,
    ) -> None:
        """Initialize the IssuanceOptions instance."""

        self.type = type
        self.cryptosuite = cryptosuite
        self.securing_mechanism = securing_mechanism
        self.verification_method = verification_method
        self.credential_id = credential_id
        self.credential_status = credential_status

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, IssuanceOptions):
            return (
                self.type == o.type
                and self.cryptosuite == o.cryptosuite
                and self.verification_method == o.verification_method
                and self.securing_mechanism == o.securing_mechanism
                and self.credential_id == o.credential_id
                and self.credential_status == o.credential_status
            )

        return False


class VerificationOptions(BaseModel):
    """Credential verification options model."""

    class Meta:
        """VerificationOptions metadata."""

        schema_class = "VerificationOptionsSchema"

    def __init__(
        self,
        checks: Optional[list] = None,
        domain: Optional[str] = None,
        challenge: Optional[str] = None,
        expected_proof_purpose: Optional[str] = None,
    ) -> None:
        """Initialize the VerificationOptions instance."""

        self.checks = checks
        self.domain = domain
        self.challenge = challenge
        self.expected_proof_purpose = expected_proof_purpose

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, VerificationOptions):
            return (
                self.checks == o.checks
                and self.domain == o.domain
                and self.challenge == o.challenge
                and self.expected_proof_purpose == o.expected_proof_purpose
            )

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

    type = fields.Str(
        data_key="type",
        required=False,
        metadata={
            "description": "The securing mechanism used for the proof.",
            "example": "DataIntegrityProof",
        },
    )

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

    credential_status = fields.Dict(
        data_key="credentialStatus",
        required=False,
        metadata={
            "description": (""),
            "example": {
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
            },
        },
    )

    credential_id = fields.Str(
        data_key="credentialId",
        required=False,
        metadata={
            "description": (""),
            "example": "",
        },
    )


class VerificationOptionsSchema(BaseModelSchema):
    """Credential verification options schema."""

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = VerificationOptions

    checks = fields.List(fields.Str(), data_key="checks", required=False)

    domain = fields.Str(data_key="domain", required=False)

    challenge = fields.Str(data_key="challenge", required=False)

    expected_proof_purpose = fields.Str(data_key="expectedProofPurpose", required=False)
