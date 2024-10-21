"""Verifiable Credential marshmallow schema classes."""

from typing import List, Optional, Union

from marshmallow import INCLUDE, fields, post_dump

from ....messaging.models.base import BaseModel, BaseModelSchema
from ....messaging.valid import (
    CREDENTIAL_CONTEXT_EXAMPLE,
    CREDENTIAL_CONTEXT_VALIDATE,
    CREDENTIAL_TYPE_EXAMPLE,
    CREDENTIAL_TYPE_VALIDATE,
    UriOrDictField,
)
from ...ld_proofs.constants import (
    CREDENTIALS_CONTEXT_V1_URL,
    CREDENTIALS_CONTEXT_V2_URL,
    VERIFIABLE_CREDENTIAL_TYPE,
)


class CredentialContext(BaseModel):
    """Credential Context model."""

    class Meta:
        """CredentialContext metadata."""

        schema_class = "CredentialContextSchema"

    def __init__(
        self,
        context: Optional[List[Union[str, dict]]] = None,
        type: Optional[List[str]] = None,
        **kwargs,
    ) -> None:
        """Initialize the CredentialContext instance."""
        self._context = context or [CREDENTIALS_CONTEXT_V1_URL]
        self._type = type or [VERIFIABLE_CREDENTIAL_TYPE]
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
        assert context[0] in [CREDENTIALS_CONTEXT_V1_URL, CREDENTIALS_CONTEXT_V2_URL]

        self._context = context

    @property
    def type(self) -> List[str]:
        """Getter for type."""
        return self._type

    @type.setter
    def type(self, type: List[str]):
        """Setter for type.

        Must contain VerifiableCredential
        """
        assert VERIFIABLE_CREDENTIAL_TYPE in type

        self._type = type

    def __eq__(self, o: object) -> bool:
        """Check equality."""
        if isinstance(o, CredentialContext):
            return (
                self.context == o.context
                and self.type == o.type
                and self.extra == o.extra
            )

        return False


class CredentialContextSchema(BaseModelSchema):
    """Credential Context schema.

    Based on https://www.w3.org/TR/vc-data-model

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = CredentialContext

    context = fields.List(
        UriOrDictField(required=True),
        data_key="@context",
        required=True,
        metadata={
            "description": "The JSON-LD context of the credential",
            "example": CREDENTIAL_CONTEXT_EXAMPLE,
        },
    )

    type = fields.List(
        fields.Str(required=True),
        required=True,
        metadata={
            "description": "The JSON-LD type of the credential",
            "example": CREDENTIAL_TYPE_EXAMPLE,
        },
    )

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data
