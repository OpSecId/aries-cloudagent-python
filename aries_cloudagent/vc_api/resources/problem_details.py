PROBLEM_DETAILS = {
    "STATUS_RETRIEVAL_ERROR": {
        "type": "https://www.w3.org/ns/credentials/status-list#STATUS_RETRIEVAL_ERROR",
        "code": "-128",
        "title": "STATUS_RETRIEVAL_ERROR",
        "detail": "Retrieval of the status list failed.",
    },
    "STATUS_VERIFICATION_ERROR": {
        "type": "https://www.w3.org/ns/credentials/status-list#STATUS_VERIFICATION_ERROR",
        "code": "-129",
        "title": "STATUS_VERIFICATION_ERROR",
        "detail": "Validation of the status entry failed.",
    },
    "STATUS_LIST_LENGTH_ERROR": {
        "type": "https://www.w3.org/ns/credentials/status-list#STATUS_LIST_LENGTH_ERROR",
        "code": "-130",
        "title": "STATUS_LIST_LENGTH_ERROR",
        "detail": "The status list length does not satisfy the minimum length required for herd privacy.",
    },
    "PARSING_ERROR": {
        "type": "https://www.w3.org/TR/vc-data-model#PARSING_ERROR",
        "code": "-64",
        "title": "PARSING_ERROR",
        "detail": "There was an error while parsing input.",
    },
    "CRYPTOGRAPHIC_SECURITY_ERROR": {
        "type": "https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR",
        "code": "-65",
        "title": "CRYPTOGRAPHIC_SECURITY_ERROR",
        "detail": "The securing mechanism for the document has detected a modification in the contents of the document since it was created; potential tampering detected.",
    },
    "MALFORMED_VALUE_ERROR": {
        "type": "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
        "code": "-66",
        "title": "MALFORMED_VALUE_ERROR",
        "detail": "The value associated with a particular property is malformed.",
    },
    "RANGE_ERROR": {
        "type": "https://www.w3.org/TR/vc-data-model#RANGE_ERROR",
        "code": "-67",
        "title": "RANGE_ERROR",
        "detail": "A provided value is outside of the expected range of an associated value, such as a given index value for an array being larger than the current size of the array.",
    },
    "PROOF_GENERATION_ERROR": {
        "type": "https://w3id.org/security#PROOF_GENERATION_ERROR",
        "code": "-16",
        "title": "PROOF_GENERATION_ERROR",
        "detail": "A request to generate a proof failed.",
    },
    "PROOF_VERIFICATION_ERROR": {
        "type": "https://w3id.org/security#PROOF_VERIFICATION_ERROR",
        "code": "-17",
        "title": "PROOF_VERIFICATION_ERROR",
        "detail": "An error was encountered during proof verification.",
    },
    "PROOF_TRANSFORMATION_ERROR": {
        "type": "https://w3id.org/security#PROOF_TRANSFORMATION_ERROR",
        "code": "-18",
        "title": "PROOF_TRANSFORMATION_ERROR",
        "detail": "An error was encountered during the transformation process.",
    },
    "INVALID_DOMAIN_ERROR": {
        "type": "https://w3id.org/security#INVALID_DOMAIN_ERROR",
        "code": "-19",
        "title": "INVALID_DOMAIN_ERROR",
        "detail": "The domain value in a proof did not match the expected value.",
    },
    "INVALID_CHALLENGE_ERROR": {
        "type": "https://w3id.org/security#INVALID_CHALLENGE_ERROR",
        "code": "-20",
        "title": "INVALID_CHALLENGE_ERROR",
        "detail": "The challenge value in a proof did not match the expected value.",
    },
}
