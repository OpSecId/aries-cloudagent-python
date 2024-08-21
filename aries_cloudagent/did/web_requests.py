"""DID routes web requests schemas."""

from marshmallow import fields
from ..messaging.models.openapi import OpenAPISchema


class DIDKeyRegistrationRequest(OpenAPISchema):
    """Request schema for registering key dids."""

    key_type = fields.Str(
        default="ed25519",
        required=False,
        metadata={
            "description": "Key Type",
            "example": "ed25519",
        },
    )


class DIDWebRegistrationRequest(OpenAPISchema):
    """Request schema for registering web dids."""

    id = fields.Str(
        required=True,
        metadata={
            "description": "Verification Method id value",
            "example": "did:web:example.com#multikey",
        },
    )

    type = fields.Str(
        default="MultiKey",
        required=False,
        metadata={
            "description": "Verification Method id value",
            "example": "MultiKey",
        },
    )

    key_type = fields.Str(
        default="ed25519",
        required=False,
        metadata={
            "description": "Key Type",
            "example": "ed25519",
        },
    )

    seed = fields.Str(
        default=None,
        required=False,
        metadata={
            "description": "Seed used to generate key pair",
            "example": "00000000000000000000000000000000",
        },
    )


class DIDRegistrationResponse(OpenAPISchema):
    """Response schema for registering web dids."""

    verification_method = fields.Dict()


class DIDKeyRegistrationResponse(OpenAPISchema):
    """Response schema for registering web dids."""

    did_document = fields.Dict()
