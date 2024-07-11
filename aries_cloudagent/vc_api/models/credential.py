"""Verifiable Credential marshmallow schema classes."""

from datetime import datetime
from typing import List, Optional, Union

from dateutil import tz
from marshmallow import INCLUDE, ValidationError, fields, post_dump

from ...messaging.models.base import BaseModel, BaseModelSchema
from ...messaging.valid import (
    DictOrDictListField,
    DIDKey,
    StrOrDictField,
    Uri,
    UriOrDictField,
)
from .validations import (
    CREDENTIAL_CONTEXT_EXAMPLE,
    CREDENTIAL_CONTEXT_VALIDATE,
    CREDENTIAL_TYPE_EXAMPLE,
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
    EVIDENCE_VALIDATE,
    EVIDENCE_EXAMPLE,
    DATA_INTEGRITY_PROOF_VALIDATE,
    DATA_INTEGRITY_PROOF_EXAMPLE,
    RFC3339_DATETIME_EXAMPLE,
    RFC3339_DATETIME_VALIDATE,
)
from ..resources.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
    EXAMPLE_CONTEXT_V2_URL,
    JWK_CONTEXT_V1_URL,
    MULTIKEY_CONTEXT_V1_URL,
    DATA_INTEGRITY_CONTEXT_V2_URL,
    VERIFIABLE_CREDENTIAL_TYPE,
)
from .proofs import DIProof, DataIntegrityProofSchema


class CredentialBase(BaseModel):
    """Credential base model."""

    class Meta:
        """CredentialBase metadata."""

        schema_class = "CredentialBaseSchema"

    def __init__(
        self,
        context: Optional[List[Union[str, dict]]] = None,
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        issuer: Optional[Union[dict, str]] = None,
        credential_schema: Optional[Union[dict, List[dict]]] = None,
        credential_subject: Optional[Union[dict, List[dict]]] = None,
        credential_status: Optional[Union[dict, List[dict]]] = None,
        refresh_service: Optional[Union[dict, List[dict]]] = None,
        terms_of_use: Optional[Union[dict, List[dict]]] = None,
        evidence: Optional[Union[dict, List[dict]]] = None,
        **kwargs,
    ) -> None:
        """Initialize the VerifiableCredential instance."""
        self._context = context
        self._id = id
        self._type = type
        self._issuer = issuer
        self._credential_subject = credential_subject
        self._credential_schema = credential_schema
        self._credential_status = credential_status
        self._refresh_service = refresh_service
        self._terms_of_use = terms_of_use
        self._evidence = evidence

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
        assert VERIFIABLE_CREDENTIAL_TYPE in type

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
    def issuer_id(self) -> Optional[str]:
        """Getter for issuer id."""
        if not self._issuer:
            return None
        elif isinstance(self._issuer, str):
            return self._issuer

        return self._issuer.get("id")

    @issuer_id.setter
    def issuer_id(self, issuer_id: str):
        """Setter for issuer id."""
        uri_validator = Uri()
        uri_validator(issuer_id)

        # Use simple string variant if possible
        if not self._issuer or isinstance(self._issuer, str):
            self._issuer = issuer_id
        else:
            self._issuer["id"] = issuer_id

    @property
    def issuer(self):
        """Getter for issuer."""
        return self._issuer

    @issuer.setter
    def issuer(self, issuer: Union[str, dict]):
        """Setter for issuer."""
        uri_validator = Uri()

        issuer_id = issuer if isinstance(issuer, str) else issuer.get("id")

        if not issuer_id:
            raise ValidationError("Issuer id is required")
        uri_validator(issuer_id)

        self._issuer = issuer

    @property
    def credential_subject_ids(self) -> List[str]:
        """Getter for credential subject ids."""
        if not self._credential_subject:
            return []
        elif isinstance(self._credential_subject, dict):
            subject_id = self._credential_subject.get("id")

            return [subject_id] if subject_id else []
        else:
            return [
                subject.get("id")
                for subject in self._credential_subject
                if subject.get("id")
            ]

    @property
    def credential_subject(self):
        """Getter for credential subject."""
        return self._credential_subject

    @credential_subject.setter
    def credential_subject(self, credential_subject: Union[dict, List[dict]]):
        """Setter for credential subject."""

        uri_validator = Uri()

        subjects = (
            [credential_subject]
            if isinstance(credential_subject, dict)
            else credential_subject
        )

        # loop trough all credential subjects and check for valid id uri
        for subject in subjects:
            if subject.get("id"):
                uri_validator(subject.get("id"))

        self._credential_subject = credential_subject

    @property
    def credential_schema(self):
        """Getter for credential schema."""
        return self._credential_schema

    @property
    def credential_status(self):
        """Getter for credential status."""
        return self._credential_status

    @property
    def terms_of_use(self):
        """Getter for terms of use."""
        return self._terms_of_use

    @property
    def refresh_service(self):
        """Getter for refresh service."""
        return self._refresh_service

    @property
    def evidence(self):
        """Getter for evidence."""
        return self._evidence

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, CredentialBase):
            return (
                self.context == o.context
                and self.id == o.id
                and self.type == o.type
                and self.issuer == o.issuer
                and self.credential_subject == o.credential_subject
                and self.credential_schema == o.credential_schema
                and self.credential_status == o.credential_status
                and self.terms_of_use == o.terms_of_use
                and self.refresh_service == o.refresh_service
                and self.evidence == o.evidence
                and self.extra == o.extra
            )

        return False


class CredentialBaseSchema(BaseModelSchema):
    """Credential base schema.

    Based on https://w3c.github.io/vc-data-model/

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = CredentialBase

    context = fields.List(
        UriOrDictField(required=True),
        data_key="@context",
        required=True,
        validate=CREDENTIAL_CONTEXT_VALIDATE,
        metadata={
            "description": "The JSON-LD context of the credential",
            "example": CREDENTIAL_CONTEXT_EXAMPLE,
        },
    )

    id = fields.Str(
        required=False,
        validate=Uri(),
        metadata={
            "description": "The ID of the credential",
            "example": "http://example.edu/credentials/1872",
        },
    )

    type = fields.List(
        fields.Str(required=True),
        required=True,
        validate=CREDENTIAL_TYPE_VALIDATE,
        metadata={
            "description": "The JSON-LD type of the credential",
            "example": CREDENTIAL_TYPE_EXAMPLE,
        },
    )

    issuer = StrOrDictField(
        required=True,
        metadata={
            "description": (
                "The JSON-LD Verifiable Credential Issuer. Either string of object with"
                " id field."
            ),
            "example": DIDKey.EXAMPLE,
        },
    )

    credential_subject = DictOrDictListField(
        required=True,
        data_key="credentialSubject",
        validate=CREDENTIAL_SUBJECT_VALIDATE,
        metadata={"example": CREDENTIAL_SUBJECT_EXAMPLE},
    )

    credential_schema = DictOrDictListField(
        required=False,
        data_key="credentialSchema",
        validate=CREDENTIAL_SCHEMA_VALIDATE,
        metadata={"example": CREDENTIAL_SCHEMA_EXAMPLE},
    )

    credential_status = DictOrDictListField(
        required=False,
        data_key="credentialStatus",
        validate=CREDENTIAL_STATUS_VALIDATE,
        metadata={"example": CREDENTIAL_STATUS_EXAMPLE},
    )

    terms_of_use = DictOrDictListField(
        required=False,
        data_key="termsOfUse",
        validate=TERMS_OF_USE_VALIDATE,
        metadata={"example": TERMS_OF_USE_EXAMPLE},
    )

    refresh_service = DictOrDictListField(
        required=False,
        data_key="refreshService",
        validate=REFRESH_SERVICE_VALIDATE,
        metadata={"example": REFRESH_SERVICE_EXAMPLE},
    )

    evidence = DictOrDictListField(
        required=False,
        data_key="evidence",
        validate=EVIDENCE_VALIDATE,
        metadata={"example": EVIDENCE_EXAMPLE},
    )

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data


class VerifiableCredentialBase(CredentialBase):
    """Verifiable Credential base model."""

    class Meta:
        """VerifiableCredentialBase metadata."""

        schema_class = "VerifiableCredentialBase"

    def __init__(
        self,
        context: Optional[List[Union[str, dict]]] = None,
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        issuer: Optional[Union[dict, str]] = None,
        credential_schema: Optional[Union[dict, List[dict]]] = None,
        credential_subject: Optional[Union[dict, List[dict]]] = None,
        credential_status: Optional[Union[dict, List[dict]]] = None,
        refresh_service: Optional[Union[dict, List[dict]]] = None,
        terms_of_use: Optional[Union[dict, List[dict]]] = None,
        evidence: Optional[Union[dict, List[dict]]] = None,
        proof: Optional[Union[dict, List[dict]]] = None,
        **kwargs,
    ) -> None:
        """Initialize the VerifiableCredential instance."""
        self._context = context
        self._id = id
        self._type = type
        self._issuer = issuer
        self._credential_subject = credential_subject
        self._credential_schema = credential_schema
        self._credential_status = credential_status
        self._refresh_service = refresh_service
        self._terms_of_use = terms_of_use
        self._evidence = evidence
        self._proof = proof

        self.extra = kwargs


class VerifiableCredentialBaseSchema(CredentialBaseSchema):
    """Verifiable credential base schema.

    Based on https://w3c.github.io/vc-data-model/

    """

    proof = fields.Nested(
        DataIntegrityProofSchema(),
        required=True,
        metadata={
            "description": "The proof of the credential",
            "example": DATA_INTEGRITY_PROOF_EXAMPLE,
        },
    )
