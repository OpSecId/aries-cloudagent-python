"""DataIntegrityProof."""

from typing import Optional

from marshmallow import INCLUDE, fields, post_dump

from ...messaging.models.base import BaseModel, BaseModelSchema
from ...messaging.valid import (
    INDY_ISO8601_DATETIME_EXAMPLE,
    INDY_ISO8601_DATETIME_VALIDATE,
    UUID4_EXAMPLE,
    Uri,
)


class DIProof(BaseModel):
    """Data Integrity Proof model."""

    class Meta:
        """DataIntegrityProof metadata."""

        schema_class = "DataIntegrityProofSchema"

    def __init__(
        self,
        type: Optional[str] = None,
        cryptosuite: Optional[str] = None,
        proof_purpose: Optional[str] = None,
        verification_method: Optional[str] = None,
        created: Optional[str] = None,
        domain: Optional[str] = None,
        challenge: Optional[str] = None,
        proof_value: Optional[str] = None,
        nonce: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize the DIProof instance."""

        self.type = type
        self.cryptosuite = cryptosuite
        self.proof_purpose = proof_purpose
        self.verification_method = verification_method
        self.created = created
        self.domain = domain
        self.challenge = challenge
        self.proof_value = proof_value
        self.nonce = nonce
        self.extra = kwargs


class DataIntegrityProofSchema(BaseModelSchema):
    """Data Integrity proof schema.

    Based on https://w3c.github.io/vc-data-integrity/

    """

    class Meta:
        """Accept parameter overload."""

        unknown = INCLUDE
        model_class = DIProof

    type = fields.Str(
        required=True,
        metadata={
            "description": (
                "Identifies the digital signature suite that was used to create the"
                " signature"
            ),
            "example": "DataIntegrityProof",
        },
    )

    cryptosuite = fields.Str(
        data_key="cryptosuite",
        required=True,
        metadata={"description": "Cryptosuite", "example": "eddsa-jcs-2022"},
    )

    proof_purpose = fields.Str(
        data_key="proofPurpose",
        required=True,
        metadata={"description": "Proof purpose", "example": "assertionMethod"},
    )

    verification_method = fields.Str(
        data_key="verificationMethod",
        required=True,
        validate=Uri(),
        metadata={
            "description": "Information used for proof verification",
            "example": (
                "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL#z6Mkgg34"
                "2Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
            ),
        },
    )

    created = fields.Str(
        required=True,
        validate=INDY_ISO8601_DATETIME_VALIDATE,
        metadata={
            "description": (
                "The string value of an ISO8601 combined date and time string generated"
                " by the Signature Algorithm"
            ),
            "example": INDY_ISO8601_DATETIME_EXAMPLE,
        },
    )

    proof_value = fields.Str(
        required=True,
        data_key="proofValue",
        metadata={
            "description": "The proof value of a proof",
            "example": ("z5WSpZRTT...3p2PD"),
        },
    )

    domain = fields.Str(
        required=False,
        metadata={
            "description": (
                "A string value specifying the restricted domain of the signature."
            ),
            "example": "https://example.com",
        },
    )

    challenge = fields.Str(
        required=False,
        metadata={
            "description": (
                "Associates a challenge with a proof, for use with a proofPurpose such"
                " as authentication"
            ),
            "example": UUID4_EXAMPLE,
        },
    )

    nonce = fields.Str(
        required=False,
        metadata={
            "description": "The nonce",
            "example": (
                "CF69iO3nfvqRsRBNElE8b4wO39SyJHPM7Gg1nExltW5vSfQA1lvDCR/zXX1To0/4NLo=="
            ),
        },
    )

    @post_dump(pass_original=True)
    def add_unknown_properties(self, data: dict, original, **kwargs):
        """Add back unknown properties before outputting."""

        data.update(original.extra)

        return data
