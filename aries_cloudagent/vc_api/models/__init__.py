from .credential_v1 import (
    Credential as Credential_V1,
    VerifiableCredential as VerifiableCredential_V1,
    CredentialSchema as CredentialSchema_V1,
    VerifiableCredentialSchema as VerifiableCredentialSchema_V1,
)
from .credential_v2 import (
    Credential as Credential_V2,
    VerifiableCredential as VerifiableCredential_V2,
    CredentialSchema as CredentialSchema_V2,
    VerifiableCredentialSchema as VerifiableCredentialSchema_V2,
)
from .proof import (
    DIProof,
    DataIntegrityProofSchema,
)
from .options import (
    IssuanceOptions,
    IssuanceOptionsSchema,
    VerificationOptions,
    VerificationOptionsSchema,
)

__all__ = [
    "Credential_V1",
    "VerifiableCredential_V1",
    "CredentialSchema_V1",
    "VerifiableCredentialSchema_V1",
    "Credential_V2",
    "VerifiableCredential_V2",
    "CredentialSchema_V2",
    "VerifiableCredentialSchema_V2",
    "DIProof",
    "DataIntegrityProofSchema",
    "IssuanceOptions",
    "IssuanceOptionsSchema",
    "VerificationOptions",
    "VerificationOptionsSchema",
]
