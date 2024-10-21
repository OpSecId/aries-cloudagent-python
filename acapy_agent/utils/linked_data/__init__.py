from processor import JsonLdProcessor

CONTEXTS = {
    "did/v1": "https://www.w3.org/ns/did/v1",
    "security/v1": "https://w3id.org/security/v1",
    "security/v2": "https://w3id.org/security/v2",
    "security/jwk/v1": "https://w3id.org/security/jwk/v1",
    "security/multikey/v1": "https://w3id.org/security/multikey/v1",
    "security/data-integrity/v2": "https://w3id.org/security/data-integrity/v2",
    "security/suites/ed25519-2020/v1": "https://w3id.org/security/suites/ed25519-2020/v1",
    "credentials/v1": "https://www.w3.org/2018/credentials/v1",
    "credentials/v2": "https://www.w3.org/ns/credentials/v2",
    "credentials/examples/v2": "https://www.w3.org/ns/credentials/examples/v2",
    "credentials/undefined-terms/v2": {
        "@vocab": "https://www.w3.org/ns/credentials/undefined-terms/v2#"
    },
}

__all__ = [
    "JsonLdProcessor",
    "CONTEXTS",
]
