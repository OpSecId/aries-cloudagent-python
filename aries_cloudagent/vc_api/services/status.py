"""Service for managing statuses of JSON-LD formatted W3C VCs."""

import logging

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor

from ...core.profile import Profile
from ..resources.problem_details import PROBLEM_DETAILS
from .verifier import VerifierService
from bitstring import BitArray
import gzip
import base64
import random
import requests


class StatusServiceError(Exception):
    """Generic Service Error."""


class StatusService:
    """Class for managing W3C VCs statuses."""

    def __init__(self, profile: Profile):
        """Initialize the VC status service."""
        self.profile = profile

    def _generate(self, status_list_bitstring):
        # https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-generation-algorithm
        status_list_bitarray = BitArray(bin=status_list_bitstring)
        status_list_compressed = gzip.compress(status_list_bitarray.bytes)
        status_list_encoded = (
            base64.urlsafe_b64encode(status_list_compressed).decode("utf-8").rstrip("=")
        )
        return status_list_encoded

    def _expand(self, status_list_encoded):
        # https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-expansion-algorithm
        status_list_compressed = base64.urlsafe_b64decode(status_list_encoded)
        status_list_bytes = gzip.decompress(status_list_compressed)
        status_list_bitarray = BitArray(bytes=status_list_bytes)
        status_list_bitstring = status_list_bitarray.bin
        return status_list_bitstring

    async def create_status_list(
        self,
        issuer=None,
        purpose="revocation",
        ttl=300000,
        length=200000,
    ):

        # https://www.w3.org/TR/vc-bitstring-status-list/#example-example-bitstringstatuslistcredential
        status_list_credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": issuer,
            "credentialSubject": {
                "type": "BitstringStatusList",
                "statusPurpose": purpose,
                "encodedList": self._generate(str(0) * length),
                "ttl": ttl,
            },
        }
        return status_list_credential

    async def create_status_entry(self, purpose):
        if not self.profile.settings.get("w3c_vc.status_list_server"):
            raise StatusServiceError("Missing status list server.")
        # https://www.w3.org/TR/vc-bitstring-status-list/#example-example-statuslistcredential
        # Find unoccupied index
        entry = {
            "type": "BitstringStatusListEntry",
            "statusPurpose": purpose,
            "statusListIndex": random.choice(
                [e for e in range(200000 - 1)]
                # [e for e in range(self.lenght - 1) if e not in status_entries]
            ),
            "statusListCredential": self.profile.settings.get(
                "w3c_vc.status_list_server"
            ),
        }

        return entry

    async def validate(
        self, credential_to_validate, minimum_number_of_entries: int = 131072
    ):
        # https://www.w3.org/TR/vc-bitstring-status-list/#validate-algorithm
        status_entries = (
            credential_to_validate["credentialStatus"]
            if isinstance(credential_to_validate["credentialStatus"], list)
            else [credential_to_validate["credentialStatus"]]
        )
        results = []
        for status_entry in status_entries:
            problem_details = []
            status_purpose = status_entry["statusPurpose"]
            status_list_credential_url = status_entry["statusListCredential"]
            r = requests.get(status_list_credential_url)
            if r.status_code != 200:
                problem_details.append(PROBLEM_DETAILS["STATUS_RETRIEVAL_ERROR"])
            status_vc = r.json()
            status_credential = status_vc.copy()
            proof = status_credential.pop(proof)
            proofs = proof if isinstance(proof, list) else [proof]
            for proof in proofs:
                verification_response = VerifierService(self.profile)._verify_di_proof(
                    status_credential, proof
                )
                if not verification_response["verified"]:
                    problem_details.append(PROBLEM_DETAILS["STATUS_VERIFICATION_ERROR"])
            status_vc_purposes = (
                status_vc["credentialStatus"]["statusPurpose"]
                if isinstance(status_vc["credentialStatus"]["statusPurpose"], list)
                else [status_vc["credentialStatus"]["statusPurpose"]]
            )
            if status_purpose not in status_vc_purposes:
                problem_details.append(PROBLEM_DETAILS["STATUS_VERIFICATION_ERROR"])
            compressed_bitstring = status_vc["credentialStatus"]["encodedList"]
            credential_index = status_entry["statusListIndex"]
            status_bitstring = self._expand(compressed_bitstring)
            status_size = (
                status_entry["statusSize"] if "statusSize" in status_entry else 1
            )
            if len(status_bitstring) / status_size > minimum_number_of_entries:
                problem_details.append(PROBLEM_DETAILS["STATUS_LIST_LENGTH_ERROR"])
            try:
                status = status_bitstring[credential_index * status_size]
            except IndexError:
                problem_details.append(PROBLEM_DETAILS["RANGE_ERROR"])
            result = {}
            result["status"] = status
            result["purpose"] = status_purpose
            result["valid"] = True if result["status"] == 0 else False
            if status_purpose == "message":
                result["message"] = next(
                    (
                        message["value"]
                        for message in status_entry["statusMessages"]
                        if message["status"] == result["status"]
                    ),
                    None,
                )
            results.append(result)
        return results
