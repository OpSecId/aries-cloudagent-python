"""VC-API Routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow.exceptions import ValidationError
from uuid_utils import uuid4

from ..admin.decorators.auth import tenant_authentication
from ..admin.request_context import AdminRequestContext
from ..config.base import InjectionError
from ..resolver.base import ResolverError
from ..wallet.base import BaseWallet
from ..wallet.error import WalletError
# from .services.issuer import IssuerService, IssuerServiceError
from .services.issuer import IssuerServiceError
from .models.web_requests import IssueCredentialRequest, IssueCredentialResponse
from .models.credential import VerifiableCredentialBase
from .models.options import IssuanceOptions


@docs(tags=["vc-api"], summary="Issue a credential")
@request_schema(IssueCredentialRequest())
@response_schema(IssueCredentialResponse(), 200, description="")
@tenant_authentication
async def issue_credential_route(request: web.BaseRequest):
    """Request handler for issuing a credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    # service = IssuerService(context.profile)
    try:
        credential = body["credential"]
        options = {} if "options" not in body else body["options"]
        options["proofType"] = options["proofType"] if 'proofType' in options else "Ed25519Signature2020"

        credential = VerifiableCredentialBase.deserialize(credential)
        options = IssuanceOptions.deserialize(options)

        # vc = await service.issue(credential, options)
        return web.json_response({"VerifiableCredentialBase": credential.serialize()}, status=201)
        return web.json_response({"VerifiableCredentialBase": vc.serialize()}, status=201)
    except (ValidationError, IssuerServiceError, WalletError, InjectionError) as err:
        return web.json_response({"message": str(err)}, status=400)


# @docs(tags=["vc-api"], summary="Verify a credential")
# @request_schema(web_schemas.VerifyCredentialRequest())
# @response_schema(web_schemas.VerifyCredentialResponse(), 200, description="")
# @tenant_authentication
# async def verify_credential_route(request: web.BaseRequest):
#     """Request handler for verifying a credential.

#     Args:
#         request: aiohttp request object

#     """
#     body = await request.json()
#     context: AdminRequestContext = request["context"]
#     manager = IssuerService(context.profile)
#     try:
#         vc = VerifiableCredentialBase.deserialize(body["VerifiableCredentialBase"])
#         result = await manager.verify_credential(vc)
#         result = result.serialize()
#         return web.json_response(result)
#     except (
#         ValidationError,
#         IssuerServiceError,
#         ResolverError,
#         ValueError,
#         WalletError,
#         InjectionError,
#     ) as err:
#         return web.json_response({"message": str(err)}, status=400)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.post("/vc/credentials/issue", issue_credential_route),
            # web.post("/vc/credentials/verify", verify_credential_route),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "vc-api",
            "description": "Endpoints for managing w3c credentials and presentations",
            "externalDocs": {
                "description": "Specification",
                "url": "https://w3c-ccg.github.io/vc-api/",
            },
        }
    )
