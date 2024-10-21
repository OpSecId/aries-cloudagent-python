"""Data Integrity admin routes."""

import logging

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow import fields
from marshmallow.exceptions import ValidationError

from vcdm.models import Credential as CredentialV2

from ...admin.decorators.auth import tenant_authentication
from ...admin.request_context import AdminRequestContext
from ...config.base import InjectionError
from ...messaging.models.openapi import OpenAPISchema
from ...wallet.error import WalletError
from ...resolver.base import ResolverError
from .models import (
    CredentialContextSchema,
    IssueCredentialOptions,
    IssueCredentialOptionsSchema,
    VerifyCredentialOptions,
    VerifyCredentialOptionsSchema,
)
from .examples import CREDENTIAL_EXAMPLE, VERIFIABLE_CREDENTIAL_EXAMPLE
from ..ld_proofs.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
)
from ..vc_ld.models.credential import VerifiableCredential
from ..vc_ld.models.options import LDProofVCOptions
from ..vc_ld.manager import VcLdpManager, VcLdpManagerError

from ..data_integrity.models.options import DataIntegrityProofOptions
from ..data_integrity.manager import DataIntegrityManager, DataIntegrityManagerError

LOGGER = logging.getLogger(__name__)


class IssueCredentialRequestSchema(OpenAPISchema):
    """Request schema to issue a Verifiable Credential."""

    credential = fields.Nested(
        CredentialContextSchema, required=True, metadata={"example": CREDENTIAL_EXAMPLE}
    )
    options = fields.Nested(
        IssueCredentialOptionsSchema,
        required=False,
        metadata={
            "example": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:web:example.com#key-01",
            }
        },
    )


class IssueCredentialResponseSchema(OpenAPISchema):
    """Response schema to adding a DI proof to a document."""

    verifiable_credential = fields.Nested(
        CredentialContextSchema,
        data_key="verifiableCredential",
        required=True,
        metadata={"example": VERIFIABLE_CREDENTIAL_EXAMPLE},
    )


class VerifyCredentialRequestSchema(OpenAPISchema):
    """Request schema to issue a Verifiable Credential."""

    verifiable_credential = fields.Nested(
        CredentialContextSchema,
        data_key="verifiableCredential",
        required=True,
        metadata={"example": VERIFIABLE_CREDENTIAL_EXAMPLE},
    )
    options = fields.Nested(
        VerifyCredentialOptionsSchema,
        required=False,
        metadata={"example": {}},
    )


class VerifyCredentialResponseSchema(OpenAPISchema):
    """Response schema to adding a DI proof to a document."""

    verifiable_credential = fields.Nested(
        CredentialContextSchema, required=True, metadata={"example": {}}
    )


@docs(tags=["vc-api"], summary="Issue a credential.")
@request_schema(IssueCredentialRequestSchema())
@response_schema(IssueCredentialResponseSchema(), description="")
@tenant_authentication
async def issue_credential_route(request: web.BaseRequest):
    """Request handler for issuing a credential.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]
    body = await request.json()

    credential = body.get("credential")
    options = body.get("options")

    try:
        # Legacy Linked Data code
        if credential["@context"][0] == CREDENTIALS_CONTEXT_V1_URL:
            manager = VcLdpManager(context.profile)

            options["proofType"] = options.pop("type", None) or "Ed25519Signature2018"

            credential = VerifiableCredential.deserialize(credential)
            options = LDProofVCOptions.deserialize(options)
            vc = await manager.issue(credential, options)
            vc = vc.serialize()

        # New Data Integrity code
        elif credential["@context"][0] == CREDENTIALS_CONTEXT_V2_URL:
            try:
                CredentialV2.model_validate(credential)
            except Exception as err:
                raise web.HTTPBadRequest(reason=err.errors()[0])
            options['proofPurpose'] = 'assertionMethod'
            options = DataIntegrityProofOptions.deserialize(options)
            async with context.session() as session:
                vc = await DataIntegrityManager(session).add_proof(credential, options)

        return web.json_response({"verifiableCredential": vc}, status=201)

    except (WalletError, VcLdpManagerError, DataIntegrityManagerError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err


@docs(tags=["vc-api"], summary="Verify a credential")
@request_schema(VerifyCredentialRequestSchema())
@response_schema(VerifyCredentialResponseSchema(), 200, description="")
@tenant_authentication
async def verify_credential_route(request: web.BaseRequest):
    """Request handler for verifying a credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    manager = VcLdpManager(context.profile)

    vc = body.get("verifiableCredential")
    options = body.get("options")

    try:
        # Legacy Linked Data code
        if vc["@context"][0] == CREDENTIALS_CONTEXT_V1_URL:
            vc = VerifiableCredential.deserialize(body["verifiableCredential"])
            result = await manager.verify_credential(vc)
            result = result.serialize()

        # New Data Integrity code
        elif vc["@context"][0] == CREDENTIALS_CONTEXT_V2_URL:
            CredentialV2.model_validate(vc)
            options = VerifyCredentialOptions.deserialize(options)
            async with context.session() as session:
                verification_response = await DataIntegrityManager(session).verify_proof(
                    vc
                )
            verification_response = verification_response.serialize()

        return web.json_response(verification_response, status=200)

    except (
        ValidationError,
        VcLdpManagerError,
        ResolverError,
        ValueError,
        WalletError,
        InjectionError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.post("/vc/credentials/issue", issue_credential_route),
            web.post("/vc/credentials/verify", verify_credential_route),
        ]
    )
