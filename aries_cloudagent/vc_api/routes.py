"""VC-API Routes."""

from aiohttp import web
from aiohttp_apispec import docs, querystring_schema, request_schema, response_schema
from marshmallow.exceptions import ValidationError
from uuid_utils import uuid4
from datetime import datetime

from ..admin.decorators.auth import tenant_authentication
from ..admin.request_context import AdminRequestContext
from ..config.base import InjectionError
from ..resolver.base import ResolverError
from ..storage.error import StorageDuplicateError, StorageError, StorageNotFoundError
from ..storage.vc_holder.base import VCHolder
from ..wallet.base import BaseWallet
from ..wallet.error import WalletError
from .resources.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
)
from .services import (
    IssuerService,
    IssuerServiceError,
    VerifierService,
    VerifierServiceError,
    StatusService,
    StatusServiceError,
)
from .models import (
    CredentialBase,
    VerifiableCredentialBase,
    IssuanceOptions,
    VerificationOptions,
)
from .models.web_requests import (
    ListCredentialsResponse,
    FetchCredentialResponse,
    CreateStatusCredentialRequest,
    CreateStatusCredentialResponse,
    IssueCredentialQueryStringSchema,
    IssueCredentialRequest,
    IssueCredentialResponse,
    VerifyCredentialRequest,
)


@docs(tags=["vc-api"], summary="Issue a credential")
# @querystring_schema(IssueCredentialQueryStringSchema())
@request_schema(IssueCredentialRequest())
@response_schema(IssueCredentialResponse(), 201, description="")
@tenant_authentication
async def issue_credential_route(request: web.BaseRequest):
    """Request handler for issuing a credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    try:
        credential = body["credential"]
        if (
            credential["@context"][0] == CREDENTIALS_CONTEXT_V1_URL
            and "issuanceDate" not in credential
        ):
            # issuanceDate is a required field in VCDM 1.1
            credential["issuanceDate"] = str(
                datetime.now().isoformat("T", "seconds") + "Z"
            )

        options = {} if "options" not in body else body["options"]
        options["cryptosuite"] = (
            options["cryptosuite"]
            if "cryptosuite" in options
            else context.profile.settings.get("w3c_vc.di_cryptosuite")
        )
        options["type"] = (
            "DataIntegrityProof"
            if "cryptosuite" in options
            else context.profile.settings.get("w3c_vc.di_cryptosuite")
        )

        if (
            "credentialStatus" in options
            and credential["@context"][0] == CREDENTIALS_CONTEXT_V2_URL
        ):
            credential["credentialStatus"] = await StatusService(
                context.profile
            ).create_status_entry(options["credentialStatus"]["statusPurpose"])
        vc = await IssuerService(context.profile).issue_credential(
            CredentialBase.deserialize(credential), IssuanceOptions.deserialize(options)
        )

        return web.json_response({"verifiableCredential": vc}, status=201)

    except (ValidationError, IssuerServiceError, WalletError, InjectionError) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Verify a credential")
@request_schema(VerifyCredentialRequest())
# @response_schema(VerifyCredentialResponse(), 200, description="")
@tenant_authentication
async def verify_credential_route(request: web.BaseRequest):
    """Request handler for verifying a credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    try:
        vc = body["verifiableCredential"]
        options = {} if "options" not in body else body["options"]
        result = await VerifierService(context.profile).verify_credential(
            CredentialBase.deserialize(vc), VerificationOptions.deserialize(options)
        )
        return web.json_response(result)
    except (
        ValidationError,
        VerifierServiceError,
        ResolverError,
        ValueError,
        WalletError,
        InjectionError,
    ) as err:
        return web.json_response({"message": str(err)}, status=400)


@docs(tags=["vc-api"], summary="Create status-list credential")
@request_schema(CreateStatusCredentialRequest())
@response_schema(CreateStatusCredentialResponse(), 201, description="")
@tenant_authentication
async def create_status_credential_route(request: web.BaseRequest):
    """Request handler for creating a status credential.

    Args:
        request: aiohttp request object

    """
    body = await request.json()
    context: AdminRequestContext = request["context"]
    try:
        status_credential = await StatusService(context.profile).create_status_list(
            issuer=body["did"],
            purpose=body["purpose"] if "purpose" in body else "revocation",
            ttl=body["ttl"] if "ttl" in body else 300000,
            length=body["length"] if "length" in body else 200000,
        )
        options = {
            "verification_method": body["verification_method"],
            "cryptosuite": "Ed25519Signature2020",
        }
        status_vc = await IssuerService(context.profile).issue_credential(
            CredentialBase.deserialize(status_credential),
            IssuanceOptions.deserialize(options),
        )
        return web.json_response({"statusCredential": status_vc}, status=201)

    except (ValidationError, IssuerServiceError, WalletError, InjectionError) as err:
        return web.json_response({"message": str(err)}, status=400)


# @docs(tags=["vc-api"], summary="Store a credential")
# async def store_credential_route(request: web.BaseRequest):
#     """Request handler for storing a credential.

#     Args:
#         request: aiohttp request object

#     """
#     body = await request.json()
#     context: AdminRequestContext = request["context"]
#     manager = VcLdpManager(context.profile)

#     try:
#         vc = body["verifiableCredential"]
#         cred_id = vc["id"] if "id" in vc else f"urn:uuid:{str(uuid4())}"
#         options = {} if "options" not in body else body["options"]

#         vc = VerifiableCredential.deserialize(vc)
#         options = LDProofVCOptions.deserialize(options)

#         await manager.verify_credential(vc)
#         await manager.store_credential(vc, options, cred_id)

#         return web.json_response({"credentialId": cred_id}, status=200)

#     except (
#         ValidationError,
#         ServiceError,
#         WalletError,
#         InjectionError,
#         StorageDuplicateError,
#     ) as err:
#         return web.json_response({"message": str(err)}, status=400)


# @docs(tags=["vc-api"], summary="Prove a presentation")
# @request_schema(web_schemas.ProvePresentationRequest())
# @response_schema(web_schemas.ProvePresentationResponse(), 200, description="")
# @tenant_authentication
# async def prove_presentation_route(request: web.BaseRequest):
#     """Request handler for proving a presentation.

#     Args:
#         request: aiohttp request object

#     """
#     context: AdminRequestContext = request["context"]
#     manager = VcLdpManager(context.profile)
#     body = await request.json()
#     try:
#         presentation = body["presentation"]
#         options = {} if "options" not in body else body["options"]

#         # We derive the proofType from the holder DID if not provided in options
#         if not options.get("proofType", None):
#             holder = presentation["holder"]
#             did = holder if isinstance(holder, str) else holder["id"]
#             async with context.session() as session:
#                 wallet: BaseWallet | None = session.inject_or(BaseWallet)
#                 info = await wallet.get_local_did(did)
#                 key_type = info.key_type.key_type

#             if key_type == "ed25519":
#                 options["proofType"] = "Ed25519Signature2020"
#             elif key_type == "bls12381g2":
#                 options["proofType"] = "BbsBlsSignature2020"

#         presentation = VerifiablePresentation.deserialize(presentation)
#         options = LDProofVCOptions.deserialize(options)
#         vp = await manager.prove(presentation, options)
#         return web.json_response({"verifiablePresentation": vp.serialize()}, status=201)

#     except (ValidationError, ServiceError, WalletError, InjectionError) as err:
#         return web.json_response({"message": str(err)}, status=400)


# @docs(tags=["vc-api"], summary="Verify a Presentation")
# @request_schema(web_schemas.VerifyPresentationRequest())
# @response_schema(web_schemas.VerifyPresentationResponse(), 200, description="")
# @tenant_authentication
# async def verify_presentation_route(request: web.BaseRequest):
#     """Request handler for verifying a presentation.

#     Args:
#         request: aiohttp request object

#     """
#     context: AdminRequestContext = request["context"]
#     manager = VcLdpManager(context.profile)
#     body = await request.json()
#     try:
#         vp = VerifiablePresentation.deserialize(body["verifiablePresentation"])
#         options = {} if "options" not in body else body["options"]
#         options = LDProofVCOptions.deserialize(options)
#         verified = await manager.verify_presentation(vp, options)
#         return web.json_response(verified.serialize(), status=200)
#     except (
#         ValidationError,
#         WalletError,
#         InjectionError,
#         ServiceError,
#         ResolverError,
#         ValueError,
#     ) as err:
#         return web.json_response({"message": str(err)}, status=400)


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            # web.get("/vc/credentials", list_credentials_route, allow_head=False),
            # web.get(
            #     "/vc/credentials/{credential_id}",
            #     fetch_credential_route,
            #     allow_head=False,
            # ),
            web.post("/vc/credentials/issue", issue_credential_route),
            web.post("/vc/credentials/verify", verify_credential_route),
            web.post("/vc/status-list", create_status_credential_route),
            # web.post("/vc/credentials/store", store_credential_route),
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
