"""Example Verifiable Credentials for OpenAPI documentation."""

CREDENTIAL_EXAMPLE = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2",
    ],
    "id": "http://university.example/credentials/58473",
    "type": ["VerifiableCredential", "ExampleAlumniCredential"],
    "issuer": "did:example:2g55q912ec3476eba2l9812ecbfe",
    "validFrom": "2010-01-01T00:00:00Z",
    "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "alumniOf": {
            "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
            "name": "Example University",
        },
    },
}

VERIFIABLE_CREDENTIAL_EXAMPLE = {
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2",
    ],
    "id": "http://university.example/credentials/58473",
    "type": ["VerifiableCredential", "ExampleAlumniCredential"],
    "issuer": "did:example:123",
    "validFrom": "2010-01-01T00:00:00Z",
    "credentialSubject": {
        "id": "did:example:abc",
        "alumniOf": {
            "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
            "name": "Example University",
        },
    },
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "verificationMethod": "did:example:123#key-01",
        "proofPurpose": "assertionMethod",
        "proofValue": "z5QLBr...m95",
    },
}
