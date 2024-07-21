
from typing import List, Optional, Union
from marshmallow import INCLUDE, ValidationError, fields, post_dump
from ...messaging.models.base import BaseModel, BaseModelSchema
from .validations import (
    CREDENTIAL_CONTEXT_EXAMPLE,
    CREDENTIAL_CONTEXT_VALIDATE,
    CREDENTIAL_TYPE_EXAMPLE,
    PRESENTATION_TYPE_VALIDATE,
    PRESENTATION_TYPE_EXAMPLE,
    VERIFIABLE_CREDENTIAL_VALIDATE,
    VERIFIABLE_CREDENTIAL_EXAMPLE,
    CREDENTIAL_TYPE_VALIDATE,
    CREDENTIAL_SUBJECT_EXAMPLE,
    CREDENTIAL_SUBJECT_VALIDATE,
    CREDENTIAL_SCHEMA_VALIDATE,
    CREDENTIAL_SCHEMA_EXAMPLE,
    CREDENTIAL_STATUS_EXAMPLE,
    CREDENTIAL_STATUS_VALIDATE,
    TERMS_OF_USE_VALIDATE,
    TERMS_OF_USE_EXAMPLE,
    REFRESH_SERVICE_VALIDATE,
    REFRESH_SERVICE_EXAMPLE,
    RENDER_METHOD_VALIDATE,
    RENDER_METHOD_EXAMPLE,
    EVIDENCE_VALIDATE,
    EVIDENCE_EXAMPLE,
    DATA_INTEGRITY_PROOF_VALIDATE,
    DATA_INTEGRITY_PROOF_EXAMPLE,
)
from ..resources.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
    EXAMPLE_CONTEXT_V2_URL,
    SECURITY_JWK_CONTEXT_V1_URL,
    SECURITY_MULTIKEY_CONTEXT_V1_URL,
    SECURITY_DATA_INTEGRITY_CONTEXT_V2_URL,
    VERIFIABLE_PRESENTATION_TYPE,
)
from ...messaging.valid import (
    DictOrDictListField,
    DIDKey,
    StrOrDictField,
    Uri,
    UriOrDictField,
    RFC3339_DATETIME_EXAMPLE,
    RFC3339_DATETIME_VALIDATE,
)
from .proof import DIProof, DataIntegrityProofSchema



class PresentationBase(BaseModel):
    """Credential base model."""

    class Meta:
        """CredentialBase metadata."""

        schema_class = "CredentialBaseSchema"

    def __init__(
        self,
        context: Optional[List[Union[str, dict]]] = None,
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        holder: Optional[Union[dict, str]] = None,
        verifiable_credential: Optional[Union[dict, List[dict]]] = None,
        proof: Optional[Union[dict, List[dict]]] = None,
        **kwargs,
    ) -> None:
        """Initialize the PresentationBase instance."""
        self._context = context
        self._id = id
        self._type = type
        self._holder = holder
        self._verifiable_credential = verifiable_credential
        self._proof = proof

        self.extra = kwargs
        

    @property
    def context(self):
        """Getter for context."""
        return self._context

    @context.setter
    def context(self, context: List[Union[str, dict]]):
        """Setter for context.

        First item must be credentials v1 or v2 url
        """
        assert context[0] in [CREDENTIALS_CONTEXT_V1_URL, CREDENTIALS_CONTEXT_V2_URL]

        self._context = context

    def add_context(self, context: Union[str, dict]):
        """Add a context to this credential."""
        self._context.append(context)

    @property
    def context_urls(self) -> List[str]:
        """Getter for context urls."""
        return [context for context in self.context if isinstance(context, str)]

    @property
    def type(self) -> List[str]:
        """Getter for type."""
        return self._type

    @type.setter
    def type(self, type: List[str]):
        """Setter for type.

        First item must be VerifiableCredential
        """
        assert VERIFIABLE_PRESENTATION_TYPE in type

        self._type = type

    def add_type(self, type: str):
        """Add a type to this credential."""
        self._type.append(type)
        

    @property
    def id(self):
        """Getter for id."""
        return self._id

    @id.setter
    def id(self, id: Union[str, None]):
        """Setter for id."""
        if id:
            uri_validator = Uri()
            uri_validator(id)

        self._id = id

    @property
    def holder_id(self) -> Optional[str]:
        """Getter for holder id."""
        if not self._holder:
            return None
        elif isinstance(self._holder, str):
            return self._holder

        return self._holder.get("id")

    @holder_id.setter
    def holder_id(self, holder_id: str):
        """Setter for holder id."""
        uri_validator = Uri()
        uri_validator(holder_id)

        # Use simple string variant if possible
        if not self._holder or isinstance(self._holder, str):
            self._holder = holder_id
        else:
            self._holder["id"] = holder_id

    @property
    def holder(self):
        """Getter for holder."""
        return self._holder

    @holder.setter
    def holder(self, holder: Union[str, dict]):
        """Setter for holder."""
        uri_validator = Uri()

        holder_id = holder if isinstance(holder, str) else holder.get("id")

        if not holder_id:
            raise ValidationError("holder id is required")
        uri_validator(holder_id)

        self._holder = holder

    @property
    def verifiable_credential_ids(self) -> List[str]:
        """Getter for verifiable credential ids."""
        if not self._verifiable_credential:
            return []
        elif isinstance(self._verifiable_credential, dict):
            subject_id = self._verifiable_credential.get("id")

            return [subject_id] if subject_id else []
        else:
            return [
                subject.get("id")
                for subject in self._verifiable_credential
                if subject.get("id")
            ]

    @property
    def verifiable_credential(self):
        """Getter for verifiable credential."""
        return self._verifiable_credential

    @verifiable_credential.setter
    def verifiable_credential(self, verifiable_credential: Union[dict, List[dict]]):
        """Setter for verifiable credential."""

        uri_validator = Uri()

        credentials = (
            [verifiable_credential]
            if isinstance(verifiable_credential, dict)
            else verifiable_credential
        )

        # loop trough all verifiable credential and check for valid id uri
        for credential in credentials:
            if credential.get("id"):
                uri_validator(credential.get("id"))

        self._verifiable_credential = verifiable_credential

    @property
    def proof(self):
        """Getter for proof."""
        return self._proof

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, PresentationBase):
            return (
                self.context == o.context
                and self.id == o.id
                and self.type == o.type
                and self.holder == o.holder
                and self.verifiable_credential == o.verifiable_credential
                and self.proof == o.proof
                and self.extra == o.extra
            )

        return False


class PresentationBaseSchema(BaseModelSchema):
    """Presentation base schema.

    Based on https://w3c.github.io/vc-data-model/

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = PresentationBase

    context = fields.List(
        UriOrDictField(required=True),
        data_key="@context",
        required=True,
        validate=CREDENTIAL_CONTEXT_VALIDATE,
        metadata={
            "example": CREDENTIAL_CONTEXT_EXAMPLE,
        },
    )

    id = fields.Str(
        required=False,
        validate=Uri(),
        metadata={
            "example": "http://example.edu/presentations/1872",
        },
    )

    type = fields.List(
        fields.Str(required=True),
        required=True,
        validate=PRESENTATION_TYPE_VALIDATE,
        metadata={
            "example": PRESENTATION_TYPE_EXAMPLE,
        },
    )

    holder = StrOrDictField(
        required=False,
        metadata={
            "description": (
                "The JSON-LD Verifiable Presentation Holder. Either string of object with"
                " id field."
            ),
            "example": DIDKey.EXAMPLE,
        },
    )

    verifiable_credential = DictOrDictListField(
        required=False,
        data_key="verifiableCredential",
        validate=VERIFIABLE_CREDENTIAL_VALIDATE,
        metadata={"example": VERIFIABLE_CREDENTIAL_EXAMPLE},
    )

    proof = fields.Nested(
        DataIntegrityProofSchema(),
        required=False,
        metadata={
            "description": "The proof of the credential",
            "example": DATA_INTEGRITY_PROOF_EXAMPLE,
        },
    )

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data
