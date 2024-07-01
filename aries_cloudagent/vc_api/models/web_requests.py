"""VC-API routes web requests schemas."""

from marshmallow import fields
from marshmallow_oneofschema import OneOfSchema
from ...messaging.models.openapi import OpenAPISchema
from . import (
    CredentialSchema_V1,
    VerifiableCredentialSchema_V1,
    CredentialSchema_V2,
    VerifiableCredentialSchema_V2,
    IssuanceOptionsSchema,
    VerificationOptionsSchema,
)

class V1orV2Schema(OneOfSchema):
    credential = {"v1": CredentialSchema_V1, "v2": CredentialSchema_V2}
    
class ListCredentialsResponse(OpenAPISchema):
    """Response schema for listing credentials."""

    results = [fields.Nested(VerifiableCredentialSchema_V1)]


class FetchCredentialResponse(OpenAPISchema):
    """Response schema for fetching a credential."""

    results = fields.Nested(VerifiableCredentialSchema_V1)


class IssueCredentialRequest(OpenAPISchema):
    """Request schema for issuing a credential."""
    
    # credential = fields.Nested(CredentialSchema_V1)
    credential = fields.Nested(CredentialSchema_V2)
    options = fields.Nested(IssuanceOptionsSchema)


class IssueCredentialResponse(OpenAPISchema):
    """Request schema for issuing a credential."""

    verifiableCredential = fields.Nested(VerifiableCredentialSchema_V1)


class VerifyCredentialRequest(OpenAPISchema):
    """Request schema for verifying a credential."""

    verifiableCredential = fields.Nested(VerifiableCredentialSchema_V1)
    options = fields.Nested(VerificationOptionsSchema)


# class VerifyCredentialResponse(OpenAPISchema):
#     """Request schema for verifying an LDP VP."""

#     results = fields.Nested(PresentationVerificationResultSchema)


# class ProvePresentationRequest(OpenAPISchema):
#     """Request schema for proving a presentation."""

#     presentation = fields.Nested(PresentationSchema)
#     options = fields.Nested(LDProofVCOptionsSchema)


# class ProvePresentationResponse(OpenAPISchema):
#     """Request schema for proving a presentation."""

#     verifiablePresentation = fields.Nested(VerifiablePresentationSchema)


# class VerifyPresentationRequest(OpenAPISchema):
#     """Request schema for verifying a credential."""

#     verifiablePresentation = fields.Nested(VerifiablePresentationSchema)
#     options = fields.Nested(LDProofVCOptionsSchema)


# class VerifyPresentationResponse(OpenAPISchema):
#     """Request schema for verifying an LDP VP."""

#     results = fields.Nested(PresentationVerificationResultSchema)
