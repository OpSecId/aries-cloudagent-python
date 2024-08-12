"""DID Management Routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow.exceptions import ValidationError

from ..wallet.key_type import KeyType, ED25519
from ..admin.decorators.auth import tenant_authentication
from ..admin.request_context import AdminRequestContext
from .models.web_requests import (
    DIDKeyRegistrationRequest,
    DIDKeyRegistrationResponse,
    DIDWebRegistrationRequest,
    DIDWebRegistrationResponse,
)
from .operators.did_web import DidWebOperator, DidOperatorError
from .operators.did_key import DidKeyOperator, DidOperatorError
import uuid

KEY_MAPPINGS = {
    'eddsa': ED25519
}


@docs(tags=["did"], summary="Register Key DID")
@request_schema(DIDKeyRegistrationRequest())
@response_schema(DIDKeyRegistrationResponse(), 201, description="")
@tenant_authentication
async def register_did_key(request: web.BaseRequest):
    """Request handler for registering a Key DID.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    try:
        key_type = KEY_MAPPINGS[body['key_type']]
        did_doc = await DidKeyOperator(context.profile).register_did(key_type)
        return web.json_response({"didDocument": did_doc}, status=201)
    except (
        KeyError,
        ValidationError,
        DidOperatorError
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["did"], summary="Register Web DID")
@request_schema(DIDWebRegistrationRequest())
@response_schema(DIDWebRegistrationResponse(), 201, description="")
@tenant_authentication
async def register_did_web(request: web.BaseRequest):
    """Request handler for registering a Web DID.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    try:
        endorser = body["endorser"] if 'endorser' in body else context.profile.settings.get('did_web.endorser')
        server = body["server"] if 'server' in body else context.profile.settings.get('did_web.server')
        identifier = body["identifier"] if 'identifier' in body else str(uuid.uuid4())
        
        if not endorser:
            return web.json_response({"message": "Must configure or provide did-web endorser value"}, status=400)
        
        if not server:
            return web.json_response({"message": "Must configure or provide did-web server value"}, status=400)
        
        did_doc = await DidWebOperator(context.profile).register_did(server, identifier, endorser)
        return web.json_response({"didDocument": did_doc}, status=201)
    except (
        KeyError,
        ValidationError,
        DidOperatorError
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


# @docs(tags=["did"], summary="Update DID")
# @request_schema(DIDWebRegistrationRequest())
# @response_schema(DIDWebRegistrationResponse(), 200, description="")
# @tenant_authentication
# async def update_did_web(request: web.BaseRequest):
#     pass


# @docs(tags=["did"], summary="Delete DID")
# @request_schema(DIDWebRegistrationRequest())
# @response_schema(DIDWebRegistrationResponse(), 200, description="")
# @tenant_authentication
# async def delete_did_web(request: web.BaseRequest):
#     pass


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.post("/did/key", register_did_key),
            web.post("/did/web", register_did_web),
            # web.put("/did/web", update_did_web),
            # web.delete("/did/web", delete_did_web),
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