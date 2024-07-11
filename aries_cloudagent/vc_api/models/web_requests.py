"""VC-API routes web requests schemas."""

from marshmallow import fields
from ...messaging.models.openapi import OpenAPISchema

from .options import IssuanceOptionsSchema
from .credential import (
    CredentialBaseSchema,
    VerifiableCredentialBaseSchema,
)


class ListCredentialsResponse(OpenAPISchema):
    """Response schema for listing credentials."""

    results = [fields.Nested(VerifiableCredentialBaseSchema)]


class FetchCredentialResponse(OpenAPISchema):
    """Response schema for fetching a credential."""

    results = fields.Nested(VerifiableCredentialBaseSchema)


class IssueCredentialRequest(OpenAPISchema):
    """Request schema for issuing a credential."""

    credential = fields.Nested(CredentialBaseSchema)
    options = fields.Nested(IssuanceOptionsSchema)


class IssueCredentialResponse(OpenAPISchema):
    """Request schema for issuing a credential."""

    verifiableCredential = fields.Nested(VerifiableCredentialBaseSchema)
