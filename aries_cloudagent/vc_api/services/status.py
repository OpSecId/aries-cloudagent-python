"""Service for managing statuses of JSON-LD formatted W3C VCs."""

import logging

from typing import Dict, List, Optional, Type, Union, cast

from pyld.jsonld import JsonLdProcessor

from ...core.profile import Profile
from bitstring import BitArray
import gzip
import base64
import random


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
