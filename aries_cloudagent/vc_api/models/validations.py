"""Validators for JSON-LD VC related schema fields."""

from marshmallow.exceptions import ValidationError
from marshmallow.fields import Field
from marshmallow.validate import OneOf, Range, Regexp, Validator


class Uri(Regexp):
    """Validate value against URI on any scheme."""

    EXAMPLE = "https://www.w3.org/ns/credentials/v2"
    PATTERN = r"\w+:(\/?\/?)[^\s]+"

    def __init__(self):
        """Initialize the instance."""
        super().__init__(Uri.PATTERN, error="Value {input} is not URI")

class NameAttribute(Validator):

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        if isinstance(value, list):
            for item in value:
                for key in item:
                    if key not in ['@value', '@language', '@direction']:
                        raise ValidationError(
                            f"Invalid extra name property {key}."
                        )
        if isinstance(value, dict):
            for key in value:
                if key not in ['@value', '@language', '@direction']:
                    raise ValidationError(
                        f"Invalid extra name property {key}."
                    )
        return value

class DescriptionAttribute(Validator):

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        if isinstance(value, list):
            for item in value:
                for key in item:
                    if key not in ['@value', '@language', '@direction']:
                        raise ValidationError(
                            f"Invalid extra description property {key}."
                        )
        if isinstance(value, dict):
            for key in value:
                if key not in ['@value', '@language', '@direction']:
                    raise ValidationError(
                        f"Invalid extra description property {key}."
                    )
        return value

class CredentialContext(Validator):
    """Credential Context."""

    V1_CONTEXT = "https://www.w3.org/2018/credentials/v1"
    V2_CONTEXT = "https://www.w3.org/ns/credentials/v2"
    EXAMPLE = [V2_CONTEXT, "https://www.w3.org/ns/credentials/examples/v2"]

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        length = len(value)

        if length < 1 or value[0] not in [
            CredentialContext.V1_CONTEXT,
            CredentialContext.V2_CONTEXT,
        ]:
            raise ValidationError(
                f"First context must be one of {CredentialContext.V1_CONTEXT} or {CredentialContext.V2_CONTEXT}"
            )

        return value


class CredentialType(Validator):
    """Credential Type."""

    CREDENTIAL_TYPE = "VerifiableCredential"
    EXAMPLE = [CREDENTIAL_TYPE, "AlumniCredential"]

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        if isinstance(value, list):
            if CredentialType.CREDENTIAL_TYPE not in value:
                raise ValidationError(f"type must include {CredentialType.CREDENTIAL_TYPE}")
        elif isinstance(value, str):
            if CredentialType.CREDENTIAL_TYPE != value:
                raise ValidationError(f"type must be {CredentialType.CREDENTIAL_TYPE}")

        return value

class PresentationType(Validator):
    """Credential Type."""

    PRESETNATION_TYPE = "VerifiablePresentation"
    EXAMPLE = [PRESETNATION_TYPE, "AlumniCredential"]

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        length = len(value)
        if length < 1 or PresentationType.PRESETNATION_TYPE not in value:
            raise ValidationError(f"type must include {PresentationType.PRESETNATION_TYPE}")

        return value


class CredentialSubject(Validator):
    """Credential subject."""

    EXAMPLE = {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "degree": {
            "type": "ExampleBachelorDegree",
            "name": "Bachelor of Science and Arts",
        },
        "alumniOf": {"name": "Example University"},
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        subjects = value if isinstance(value, list) else [value]

        for subject in subjects:
            if subject == {}:
                raise ValidationError(f"credential subject can't be empty")
            if "id" in subject:
                uri_validator = Uri()
                try:
                    uri_validator(subject["id"])
                except ValidationError:
                    raise ValidationError(
                        f'credential subject id {subject["id"]} must be URI'
                    ) from None

        return value


class VerifiableCredential(Validator):
    """Credential subject."""

    EXAMPLE = {
        "name": "Alice"
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        credentials = value if isinstance(value, list) else [value]

        for credential in credentials:
            if credential == {}:
                raise ValidationError(f"verifiable credential can't be empty")
            if "id" in credential:
                uri_validator = Uri()
                try:
                    uri_validator(credential["id"])
                except ValidationError:
                    raise ValidationError(
                        f'credential subject id {credential["id"]} must be URI'
                    ) from None

        return value


class CredentialSchema(Validator):
    """Credential schema."""

    EXAMPLE = [
        {"id": "https://example.org/examples/degree.json", "type": "JsonSchema"},
        {"id": "https://example.org/examples/alumni.json", "type": "JsonSchema"},
    ]

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        schemas = value if isinstance(value, list) else [value]

        for schema in schemas:
            if "id" not in schema or "type" not in schema:
                raise ValidationError(
                    f"credential schema MUST have an id or a type"
                ) from None

            uri_validator = Uri()
            try:
                uri_validator(schema["id"])
            except ValidationError:
                raise ValidationError(
                    f'credential status id {schema["id"]} must be URI'
                ) from None

        return value


class CredentialStatus(Validator):
    """Credential status."""

    EXAMPLE = {
        "id": "https://example.com/credentials/status/3#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "94567",
        "statusListCredential": "https://example.com/credentials/status/3",
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        status_entries = value if isinstance(value, list) else [value]

        for status_entry in status_entries:
            if "type" not in status_entry:
                raise ValidationError(f"credential status MUST have a type") from None

            uri_validator = Uri()
            if "id" in status_entry:
                try:
                    uri_validator(status_entry["id"])
                except ValidationError:
                    raise ValidationError(
                        f'credential status id {status_entry["id"]} must be URI'
                    ) from None

        return value


class TermsOfUse(Validator):
    """Terms of use."""

    EXAMPLE = {
        "id": "https://api-test.ebsi.eu/trusted-issuers-registry/v4/issuers/did:ebsi:zz7XsC9ixAXuZecoD9sZEM1/attributes/7201d95fef05f72667f5454c2192da2aa30d9e052eeddea7651b47718d6f31b0",
        "type": "IssuanceCertificate",
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        terms_of_use = value if isinstance(value, list) else [value]

        for term in terms_of_use:
            if "type" not in term:
                raise ValidationError(f"terms of use MUST have a type") from None

        return value


class RefreshService(Validator):
    """Refresh service."""

    EXAMPLE = {
        "type": "VerifiableCredentialRefreshService2021",
        "url": "https://university.example/workflows/refresh-degree",
        "validFrom": "2021-09-01T19:23:24Z",
        "validUntil": "2022-02-01T19:23:24Z",
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        refresh_services = value if isinstance(value, list) else [value]

        for service in refresh_services:
            if "type" not in service:
                raise ValidationError(
                    f"refresh service of use MUST have a type"
                ) from None

        return value


class RenderMethod(Validator):
    """Render Method."""

    EXAMPLE = {"type": "OverlayCaptureBundle", "id": "https://example.com/my-bundle"}

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        render_methods = value if isinstance(value, list) else [value]

        for method in render_methods:
            if "id" not in method or "type" not in method:
                raise ValidationError(
                    f"Render Method of use MUST have an id and a type"
                ) from None

            uri_validator = Uri()
            try:
                uri_validator(method["id"])
            except ValidationError:
                raise ValidationError(
                    f'refresh service of use id {method["id"]} must be URI'
                ) from None

        return value


class Evidence(Validator):
    """Evidence."""

    EXAMPLE = {
        "type": "VerifiableCredentialRefreshService2021",
        "url": "https://university.example/workflows/refresh-degree",
        "validFrom": "2021-09-01T19:23:24Z",
        "validUntil": "2022-02-01T19:23:24Z",
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        evidences = value if isinstance(value, list) else [value]

        for evidence in evidences:
            if "type" not in evidence:
                raise ValidationError(f"Evidence MUST have a type") from None

        return value


class DataIntegrityProof(Validator):
    """Evidence."""

    EXAMPLE = {
        "type": "Ed25519Signature2020",
        "verificationMethod": (
            "did:key:z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38Ee"
            "fXmgDL#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL"
        ),
        "created": "2019-12-11T03:50:55",
        "proofPurpose": "assertionMethod",
        "proofValue": (
            "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0JiNjQiXX0..lKJU0Df_k"
            "eblRKhZAS9Qq6zybm-HqUXNVZ8vgEPNTAjQKBhQDxvXNo7nvtUBb_Eq1Ch6YBKY5qBQ"
        ),
    }

    def __init__(self) -> None:
        """Initialize the instance."""
        super().__init__()

    def __call__(self, value):
        """Validate input value."""
        proofs = value if isinstance(value, list) else [value]

        for proof in proofs:
            if "type" not in proof:
                raise ValidationError(f"Proof MUST have a type") from None

            uri_validator = Uri()
            try:
                uri_validator(proof["verificationMethod"])
            except ValidationError:
                raise ValidationError(
                    f'Evidence of use id {proof["verificationMethod"]} must be URI'
                ) from None

        return value


URI_VALIDATE = Uri()
URI_EXAMPLE = Uri.EXAMPLE

CREDENTIAL_TYPE_VALIDATE = CredentialType()
CREDENTIAL_TYPE_EXAMPLE = CredentialType.EXAMPLE

VERIFIABLE_CREDENTIAL_VALIDATE = VerifiableCredential()
VERIFIABLE_CREDENTIAL_EXAMPLE = VerifiableCredential.EXAMPLE

PRESENTATION_TYPE_VALIDATE = PresentationType()
PRESENTATION_TYPE_EXAMPLE = PresentationType.EXAMPLE

CREDENTIAL_CONTEXT_VALIDATE = CredentialContext()
CREDENTIAL_CONTEXT_EXAMPLE = CredentialContext.EXAMPLE

CREDENTIAL_SUBJECT_VALIDATE = CredentialSubject()
CREDENTIAL_SUBJECT_EXAMPLE = CredentialSubject.EXAMPLE

CREDENTIAL_SCHEMA_VALIDATE = CredentialSchema()
CREDENTIAL_SCHEMA_EXAMPLE = CredentialSchema.EXAMPLE

CREDENTIAL_STATUS_VALIDATE = CredentialStatus()
CREDENTIAL_STATUS_EXAMPLE = CredentialStatus.EXAMPLE

TERMS_OF_USE_VALIDATE = TermsOfUse()
TERMS_OF_USE_EXAMPLE = TermsOfUse.EXAMPLE

REFRESH_SERVICE_VALIDATE = RefreshService()
REFRESH_SERVICE_EXAMPLE = RefreshService.EXAMPLE

RENDER_METHOD_VALIDATE = RenderMethod()
RENDER_METHOD_EXAMPLE = RenderMethod.EXAMPLE

EVIDENCE_VALIDATE = Evidence()
EVIDENCE_EXAMPLE = Evidence.EXAMPLE

DATA_INTEGRITY_PROOF_VALIDATE = DataIntegrityProof()
DATA_INTEGRITY_PROOF_EXAMPLE = DataIntegrityProof.EXAMPLE
