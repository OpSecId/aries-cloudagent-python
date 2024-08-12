
from ...wallet.key_type import KeyType, ED25519
import requests
import base58
from ...wallet.did_method import KEY
from ...wallet.base import BaseWallet

class DidOperatorError(Exception):
    """Generic Operator Error."""


class DidKeyOperator:
    """Operator for managing key dids."""

    def __init__(self, profile):
        """Initialize a new `DidKeyOperator` instance.
        """
        self.profile = profile



    async def register_did(
        self,
        key_type: KeyType = ED25519,
    ):
        """Create, store and register a new key DID.

        Args:
            key_type: The key type to use for the DID

        Returns:
            A `DIDDocument` instance representing the created DID

        Raises:
            DidWebOperatorError: If the an error occures during did registration

        """
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
        info = await wallet.create_local_did(
            method=KEY, key_type=ED25519
        )
        did_doc = {
            "id": info.did
        }
        return did_doc
        
        