"""VC-API Routes."""

from aiohttp import web
from aiohttp_apispec import docs, request_schema, response_schema
from marshmallow.exceptions import ValidationError
from uuid_utils import uuid4

from ..admin.decorators.auth import tenant_authentication
from ..admin.request_context import AdminRequestContext
from ..config.base import InjectionError
from ..resolver.base import ResolverError
from ..storage.error import StorageDuplicateError, StorageError, StorageNotFoundError
from ..wallet.error import WalletError
from .services import IssuerService, VerifierService, HolderService, ServiceError
from .models import web_schemas


@docs(tags=["vc-api"], summary="List credentials")
@tenant_authentication
async def list_credentials_route(request: web.BaseRequest):
    """Request handler for listing credentials."""

    context: AdminRequestContext = request["context"]
    try:
        records = await HolderService(context.profile).get_credentials()
        return web.json_response(records, status=200)
    except (StorageError, StorageNotFoundError) as err:
        return web.json_response({"message": err.roll_up}, status=400)


@docs(tags=["vc-api"], summary="Fetch credential by ID")
@tenant_authentication
async def fetch_credential_route(request: web.BaseRequest):
    """Request handler for returning a credential."""

    context: AdminRequestContext = request["context"]
    try:
        credential_id = request.match_info["credential_id"].strip('"')
        record = await HolderService(context.profile).get_credential(credential_id)
        return web.json_response(record.serialize()["cred_value"], status=200)
    except (StorageError, StorageNotFoundError) as err:
        return web.json_response({"message": err.roll_up}, status=400)


@docs(tags=["vc-api"], summary="Issue a credential")
@request_schema(web_schemas.IssueCredentialRequest())
# @response_schema(web_schemas.IssueCredentialResponse(), 200, description="")
@tenant_authentication
async def issue_credential_route(request: web.BaseRequest):
    """Request handler for issuing a credential."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    try:
        credential = body["credential"]
        options = body["options"] if "options" in body else {}

        vc = await IssuerService(context.profile).issue_credential(credential, options)
        return web.json_response({"verifiableCredential": vc}, status=201)

    except (ValidationError, ServiceError, WalletError, InjectionError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Verify a credential")
@request_schema(web_schemas.StoreCredentialRequest())
# @response_schema(web_schemas.VerifyCredentialResponse(), 200, description="")
@tenant_authentication
async def verify_credential_route(request: web.BaseRequest):
    """Request handler for verifying a credential."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    try:
        vc = body["verifiableCredential"]
        options = body["options"] if "options" in body else {}
        result = await VerifierService(context.profile).verify_credential(vc, options)
        return web.json_response(result.serialize())
    except (
        ValidationError,
        ServiceError,
        ResolverError,
        ValueError,
        WalletError,
        InjectionError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Store a credential")
@request_schema(web_schemas.VerifyCredentialRequest())
# @response_schema(web_schemas.VerifyCredentialResponse(), 200, description="")
async def store_credential_route(request: web.BaseRequest):
    """Request handler for storing a credential."""
    context: AdminRequestContext = request["context"]
    body = await request.json()

    try:
        vc = body["verifiableCredential"]
        options = {} if "options" not in body else body["options"]

        await VerifierService(context.profile).verify_credential(vc, options)
        if 'credentialId' not in options:
            options['credentialId'] = vc["id"] if "id" in vc else f"urn:uuid:{str(uuid4())}"
        await HolderService(context.profile).store_credential(vc, options)

        return web.json_response({"credentialId": options['credentialId']}, status=200)

    except (
        ValidationError,
        ServiceError,
        WalletError,
        InjectionError,
        StorageDuplicateError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Prove a presentation")
@tenant_authentication
async def prove_presentation_route(request: web.BaseRequest):
    """Request handler for creating a presentation."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    try:
        presentation = body["presentation"]
        options = {} if "options" not in body else body["options"]

        options["proofType"] = "Ed25519Signature2020"
        vp = await HolderService(context.profile).create_presentation(
            presentation, options
        )
        return web.json_response({"verifiablePresentation": vp.serialize()}, status=201)

    except (ValidationError, ServiceError, WalletError, InjectionError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Verify a Presentation")
@tenant_authentication
async def verify_presentation_route(request: web.BaseRequest):
    """Request handler for verifying a presentation."""
    context: AdminRequestContext = request["context"]
    body = await request.json()
    try:
        vp = body["verifiablePresentation"]
        options = {} if "options" not in body else body["options"]
        verified = await VerifierService(context.profile).verify_presentation(
            vp, options
        )
        return web.json_response(verified.serialize(), status=200)
    except (
        ValidationError,
        WalletError,
        InjectionError,
        ServiceError,
        ResolverError,
        ValueError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/vc/credentials", list_credentials_route, allow_head=False),
            web.get(
                "/vc/credentials/{credential_id}",
                fetch_credential_route,
                allow_head=False,
            ),
            web.post("/vc/credentials/issue", issue_credential_route),
            web.post("/vc/credentials/store", store_credential_route),
            web.post("/vc/credentials/verify", verify_credential_route),
            # web.post("/vc/presentations/prove", prove_presentation_route),
            # web.post("/vc/presentations/verify", verify_presentation_route),
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
