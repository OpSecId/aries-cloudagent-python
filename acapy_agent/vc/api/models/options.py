"""DataIntegrityProof."""

from typing import Optional

from marshmallow import INCLUDE, fields, post_dump

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.valid import (
    UUID4_EXAMPLE,
    Uri,
)


class IssueCredentialOptions(BaseModel):
    """Issue Credential Options model."""

    class Meta:
        """IssueCredentialOptions metadata."""

        schema_class = "IssueCredentialOptionsSchema"

    def __init__(
        self,
        type: Optional[str] = None,
        cryptosuite: Optional[str] = None,
        verification_method: Optional[str] = None,
        credential_id: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize the IssueCredentialOptions instance."""

        self.type = type
        self.cryptosuite = cryptosuite
        self.verification_method = verification_method
        self.credential_id = credential_id
        self.extra = kwargs


class IssueCredentialOptionsSchema(BaseModelSchema):
    """Issue Credential Options schema.

    Based on https://w3c-ccg.github.io/vc-api/#options

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = IssueCredentialOptions

    type = fields.Str(
        required=False,
        metadata={
            "description": "",
            "example": "DataIntegrityProof",
        },
    )

    cryptosuite = fields.Str(
        required=False,
        metadata={
            "description": "",
            "example": "eddsa-jcs-2022",
        },
    )

    verification_method = fields.Str(
        data_key="verificationMethod",
        required=False,
        validate=Uri(),
        metadata={
            "description": "",
            "example": "did:web:example.com#key-01",
        },
    )

    credential_id = fields.Str(
        data_key="credentialId",
        required=False,
        metadata={
            "description": "",
            "example": UUID4_EXAMPLE,
        },
    )

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data


class VerifyCredentialOptions(BaseModel):
    """Verify Credential Options model."""

    class Meta:
        """VerifyCredentialOptions metadata."""

        schema_class = "VerifyCredentialOptionsSchema"

    def __init__(
        self,
        **kwargs,
    ) -> None:
        """Initialize the IssueCredentialOptions instance."""

        self.extra = kwargs


class VerifyCredentialOptionsSchema(BaseModelSchema):
    """Verify Credential Options schema.

    Based on https://w3c-ccg.github.io/vc-api/#options

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = VerifyCredentialOptions

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data
