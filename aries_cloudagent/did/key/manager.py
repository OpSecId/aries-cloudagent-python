"""DID Key manager class."""

from ...wallet.key_type import KeyType
from ...wallet.did_method import KEY
from ...wallet.base import BaseWallet
from ...core.profile import Profile


class DidKeyManager:
    """Class for managing key dids."""

    def __init__(self, profile: Profile):
        """Initialize a new `DidKeyManager` instance."""
        self.profile = profile

    async def register(
        self,
        key_type: KeyType,
    ):
        """Register a new key DID.

        Args:
            key_type: The key type to use for the DID

        Returns:
            A `DIDDocument` instance representing the created DID

        Raises:
            DidOperationError: If the an error occures during did registration

        """
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
        info = await wallet.create_local_did(method=KEY, key_type=key_type)
        did = info.did
        multikey = did.split(":")[-1]
        verification_method = f"{did}#{multikey}"
        return {
            "id": verification_method,
            "type": "MultiKey",
            "controller": did,
            "publicKeyMultibase": multikey,
        }