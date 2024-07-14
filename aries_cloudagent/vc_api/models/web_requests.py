"""VC-API routes web requests schemas."""

from marshmallow import fields
from ...messaging.models.openapi import OpenAPISchema
from . import (
    CredentialBaseSchema,
    VerifiableCredentialBaseSchema,
    IssuanceOptionsSchema,
    VerificationOptionsSchema,
)


class IssueCredentialQueryStringSchema(OpenAPISchema):
    """Parameters and validators for DID list request query string."""

    suite = fields.Str(
        required=False,
        # validate=GENERIC_DID_VALIDATE,
        metadata={
            "description": "Cryptosuite to use with Data Integrity",
            "example": "eddsa-jcs-2022",
        },
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


class VerifyCredentialRequest(OpenAPISchema):
    """Request schema for verifying a credential."""

    verifiableCredential = fields.Nested(VerifiableCredentialBaseSchema)
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
