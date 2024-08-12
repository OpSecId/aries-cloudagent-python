"""DID routes web requests schemas."""

from marshmallow import fields
from ...messaging.models.openapi import OpenAPISchema

class DIDKeyRegistrationRequest(OpenAPISchema):
    """Request schema for registering key dids."""
    key_type = fields.Str(
        default="eddsa",
        required=False,
        metadata={
            "description": "Key Type",
            "example": "eddsa",
        }
    )

class DIDKeyRegistrationResponse(OpenAPISchema):
    """Response schema for registering web dids."""
    did_document = fields.Dict()
    

class DIDWebRegistrationRequest(OpenAPISchema):
    """Request schema for registering web dids."""
    server = fields.Str(
        required=False,
        metadata={
            "description": "DID Web Server Endpoint",
            "example": "https://identifier.me",
        }
    )
    identifier = fields.Str(
        required=False,
        metadata={
            "description": "DID Web Identifier",
            "example": "example",
        }
    )
    endorser = fields.Str(
        required=False,
        metadata={
            "description": "Endorser DID Key",
            "example": "did:key:z6MkfbN2dcXBS1siZLi54jM5wbbRk7SRyD6RYBNk3BhtvzE1",
        }
    )

class DIDWebRegistrationResponse(OpenAPISchema):
    """Response schema for registering web dids."""
    did_document = fields.Dict()