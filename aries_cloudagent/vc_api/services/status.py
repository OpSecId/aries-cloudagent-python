"""Services for performing Data Integrity Proof signatures over JSON-LD formatted W3C VCs."""

from ...core.profile import Profile
from . import IssuerService
from bitstring import BitArray
from datetime import datetime
import gzip
import base64
import uuid
import random


class StatusService:
    """VC-API Status service."""

    def __init__(self, profile: Profile):
        """Initialize the issuer service."""
        self.profile = profile
        
    def _generate_(self, status_list_bitstring):
        # https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-generation-algorithm
        status_list_bitarray = BitArray(bin=status_list_bitstring)
        status_list_compressed = gzip.compress(status_list_bitarray.bytes)
        status_list_encoded = base64.urlsafe_b64encode(status_list_compressed).decode(
            "utf-8"
        )
        return status_list_encoded
        
    def _expand_(self, status_list_encoded):
        # https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-expansion-algorithm
        status_list_compressed = base64.urlsafe_b64decode(status_list_encoded)
        status_list_bytes = gzip.decompress(status_list_compressed)
        status_list_bitarray = BitArray(bytes=status_list_bytes)
        status_list_bitstring = status_list_bitarray.bin
        return status_list_bitstring
        
    async def create_status_credential(self, issuer, lenght=200000, purpose='revocation'):
        # https://www.w3.org/TR/vc-bitstring-status-list/#example-example-bitstringstatuslistcredential
        status_list_credential = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2"
            ],
            "id": f"urn:uuid:{str(uuid.uuid5(uuid.NAMESPACE_URL, issuer))}",
            "issuer": issuer,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "credentialSubject": {
                "type": "BitstringStatusList",
                "encodedList": self._generate_(str(0) * lenght),
                "statusPurpose": purpose,
            },
        }
        return status_list_credential

    async def get_status_credential(self, credential_id):
        credential_id = f"urn:uuid:{credential_id}"
        status_list_credential = {}
        status_list_credential['validFrom'] = str(datetime.now().isoformat())
        status_list_credential['validUntil'] = str(datetime.now().isoformat())
        return await IssuerService(self.profile).issue_credential(status_list_credential)

    async def create_entry(self, issuer, status, endpoint):
        # https://www.w3.org/TR/vc-bitstring-status-list/#example-example-statuslistcredential
        status_entries = []
        lenght = 20000
        # Find an unoccupied index
        status_index = random.choice(
            [e for e in range(lenght - 1) if e not in status_entries]
        )
        status_entries.append(status_index)
        
        credential_status = {
            "id": f"urn:uuid:{str(uuid.uuid5(uuid.NAMESPACE_URL, issuer))}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": status["statusPurpose"],
            "statusListIndex": status_index,
            "statusListCredential": f"{endpoint}/{str(uuid.uuid5(uuid.NAMESPACE_URL, issuer))}"
        }

        return credential_status