"""DID Management Routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow.exceptions import ValidationError

from ..wallet.key_type import ED25519
from ..admin.decorators.auth import tenant_authentication
from ..admin.request_context import AdminRequestContext
from .web_requests import (
    DIDKeyRegistrationRequest,
    DIDKeyRegistrationResponse,
    DIDWebRegistrationRequest,
    DIDRegistrationResponse,
)
from . import DidOperationError, DidKeyManager, DidWebManager

KEY_MAPPINGS = {"ed25519": ED25519}


@docs(tags=["did"], summary="Register Key DID")
@request_schema(DIDKeyRegistrationRequest())
@response_schema(DIDRegistrationResponse(), 201, description="Register new DID key")
@tenant_authentication
async def register_did_key(request: web.BaseRequest):
    """Request handler for registering a Key DID.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    try:
        key_type = body["key_type"]
        verification_method = await DidKeyManager(context.profile).register(KEY_MAPPINGS[key_type])
        return web.json_response({"verificationMethod": verification_method}, status=201)
    except (KeyError, ValidationError, DidOperationError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["did"], summary="Register Web DID")
@request_schema(DIDWebRegistrationRequest())
@response_schema(DIDRegistrationResponse(), 201, description="Register new DID key")
@tenant_authentication
async def register_did_web(request: web.BaseRequest):
    """Request handler for registering a Key DID.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    try:
        verification_method = await DidWebManager(context.profile).\
            register(
                kid=body["id"],
                kid_type=body["type"],
                key_type=KEY_MAPPINGS[body["key_type"]],
                seed=body["seed"]
                )
        return web.json_response({"verificationMethod": verification_method}, status=201)
    except (KeyError, ValidationError, DidOperationError) as err:
        return web.json_response({"message": str(err)}, status=400)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.post("/did/key", register_did_key),
            web.post("/did/web", register_did_web),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "did",
            "description": "Endpoints for managing dids",
            "externalDocs": {
                "description": "Specification",
                "url": "https://www.w3.org/TR/did-core/",
            },
        }
    )
