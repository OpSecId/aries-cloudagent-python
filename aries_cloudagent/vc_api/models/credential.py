"""Verifiable CredentialV2 marshmallow schema classes."""

from datetime import datetime
from typing import List, Optional, Union

from dateutil import tz
from marshmallow import INCLUDE, ValidationError, fields, post_dump

from ...messaging.models.base import BaseModel, BaseModelSchema
from ...messaging.valid import (
    CREDENTIAL_V2_CONTEXT_EXAMPLE,
    UUID4_EXAMPLE,
    CREDENTIAL_V2_CONTEXT_VALIDATE,
    CREDENTIAL_STATUS_EXAMPLE,
    CREDENTIAL_STATUS_VALIDATE,
    CREDENTIAL_SUBJECT_EXAMPLE,
    CREDENTIAL_SUBJECT_VALIDATE,
    CREDENTIAL_TYPE_EXAMPLE,
    CREDENTIAL_TYPE_VALIDATE,
    RFC3339_DATETIME_EXAMPLE,
    RFC3339_DATETIME_VALIDATE,
    DictOrDictListField,
    DIDKey,
    StrOrDictField,
    Uri,
    UriOrDictField,
)
from ..proofs.constants import (
    VERIFIABLE_CREDENTIAL_TYPE,
)
from .data_integrity_proof import DataIntegrityProof, DataIntegrityProofSchema


class VerifiableCredential(BaseModel):
    """Verifiable CredentialV2 model."""

    class Meta:
        """VerifiableCredential metadata."""

        schema_class = "CredentialSchema"

    def __init__(
        self,
        context: Optional[List[Union[str, dict]]] = None,
        id: Optional[str] = None,
        type: Optional[List[str]] = None,
        issuer: Optional[Union[dict, str]] = None,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        credential_subject: Optional[Union[dict, List[dict]]] = None,
        credential_status: Optional[Union[dict, List[dict]]] = None,
        proof: Optional[Union[dict, DataIntegrityProof]] = None,
        **kwargs,
    ) -> None:
        """Initialize the VerifiableCredential instance."""
        self._context = context or [CREDENTIAL_V2_CONTEXT_EXAMPLE]
        self._id = id
        self._type = type or [VERIFIABLE_CREDENTIAL_TYPE]
        self._issuer = issuer
        self._credential_subject = credential_subject
        self._credential_status = credential_status

        # TODO: proper date parsing
        self._valid_from = valid_from
        self._valid_until = valid_until

        self._proof = proof

        self.extra = kwargs

    @property
    def context(self):
        """Getter for context."""
        return self._context

    @context.setter
    def context(self, context: List[Union[str, dict]]):
        """Setter for context.

        First item must be credentials v1 url
        """
        assert context[0] == CREDENTIAL_V2_CONTEXT_EXAMPLE

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
    def valid_from(self):
        """Getter for valid from date."""
        return self._valid_from

    @valid_from.setter
    def valid_from(self, date: Union[str, datetime]):
        """Setter for valid from date."""
        if isinstance(date, datetime):
            if not date.tzinfo:
                date = date.replace(tzinfo=tz.UTC)
            date = date.isoformat()

        self._valid_from = date

    @property
    def valid_until(self):
        """Getter for valid until date."""
        return self._valid_until

    @valid_until.setter
    def valid_until(self, date: Union[str, datetime, None]):
        """Setter for valid until date."""
        if isinstance(date, datetime):
            if not date.tzinfo:
                date = date.replace(tzinfo=tz.UTC)
            date = date.isoformat()

        self._valid_until = date

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
    def credential_status(self):
        """Getter for credential status."""
        return self._credential_status

    @property
    def proof(self):
        """Getter for proof."""
        return self._proof

    @proof.setter
    def proof(self, proof: DataIntegrityProof):
        """Setter for proof."""
        self._proof = proof

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, VerifiableCredential):
            return (
                self.context == o.context
                and self.id == o.id
                and self.type == o.type
                and self.issuer == o.issuer
                and self.valid_from == o.valid_from
                and self.valid_until == o.valid_until
                and self.credential_subject == o.credential_subject
                and self.credential_status == o.credential_status
                and self.proof == o.proof
                and self.extra == o.extra
            )

        return False


class CredentialSchema(BaseModelSchema):
    """Linked data credential schema.

    Based on https://www.w3.org/TR/vc-data-model

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = VerifiableCredential

    context = fields.List(
        UriOrDictField(required=True),
        data_key="@context",
        required=True,
        validate=CREDENTIAL_V2_CONTEXT_VALIDATE,
        metadata={
            "description": "The JSON-LD context of the credential",
            "example": ["https://www.w3.org/ns/credentials/v2"],
        },
    )

    id = fields.Str(
        required=False,
        validate=Uri(),
        metadata={
            "description": "The ID of the credential",
            "example": f"urn:uuid:{UUID4_EXAMPLE}",
        },
    )

    type = fields.List(
        fields.Str(required=True),
        required=True,
        validate=CREDENTIAL_TYPE_VALIDATE,
        metadata={
            "description": "The JSON-LD type of the credential",
            "example": ["VerifiableCredential"],
        },
    )

    issuer = StrOrDictField(
        required=True,
        metadata={
            "description": (
                "The JSON-LD Verifiable CredentialV2 Issuer. Either string of object with"
                " id field."
            ),
            "example": DIDKey.EXAMPLE,
        },
    )

    valid_from = fields.Str(
        data_key="validFrom",
        required=False,
        validate=RFC3339_DATETIME_VALIDATE,
        metadata={
            "description": "The valid from date",
            "example": RFC3339_DATETIME_EXAMPLE,
        },
    )

    valid_until = fields.Str(
        data_key="validUntil",
        required=False,
        validate=RFC3339_DATETIME_VALIDATE,
        metadata={
            "description": "The valid until date",
            "example": RFC3339_DATETIME_EXAMPLE,
        },
    )

    credential_subject = DictOrDictListField(
        required=True,
        data_key="credentialSubject",
        validate=CREDENTIAL_SUBJECT_VALIDATE,
        metadata={"example": {"id": f"{DIDKey.EXAMPLE}"}},
    )

    credential_status = DictOrDictListField(
        required=False,
        data_key="credentialStatus",
        validate=CREDENTIAL_STATUS_VALIDATE,
        metadata={"example": CREDENTIAL_STATUS_EXAMPLE},
    )

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data


class VerifiableCredentialSchema(CredentialSchema):
    """Data integrity verifiable credential schema.

    Based on https://www.w3.org/TR/vc-data-model

    """

    proof = fields.Nested(
        DataIntegrityProofSchema(),
        required=False,
        metadata={
            "description": "The proof of the credential",
            "example": {
                "type": "Ed25519Signature2020",
                "verificationMethod": ("did:web:example.com#verkey"),
                "created": "2019-12-11T03:50:55",
                "proofPurpose": "assertionMethod",
                "proofValue": (
                    "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0JiNjQiXX0..lKJU0Df_k"
                    "eblRKhZAS9Qq6zybm-HqUXNVZ8vgEPNTAjQKBhQDxvXNo7nvtUBb_Eq1Ch6YBKY5qBQ"
                ),
            },
        },
    )
