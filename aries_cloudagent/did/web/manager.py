"""DID Web manager class."""

from typing import Optional
from ...wallet.key_type import KeyType, ED25519
from ...wallet.did_method import WEB
from ...wallet.base import BaseWallet
from ...core.profile import Profile
import base58
import base64


class DidWebManager:
    """Class for managing key dids."""

    def __init__(self, profile: Profile):
        """Initialize a new `DidKeyManager` instance."""
        self.profile = profile

    async def register(
        self,
        kid: str,
        kid_type: str,
        key_type: KeyType,
        seed: Optional[str],
    ):
        """Register a new key DID.

        Args:
            key_type: The key type to use for the DID

        Returns:
            A `DIDDocument` instance representing the created DID

        Raises:
            DidOperationError: If the an error occures during did registration

        """
        did = kid.split('#')[0]
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
            
        info = await wallet.create_local_did(method=WEB, key_type=key_type, did=did, seed=seed)
        # await wallet.assign_kid_to_key(verkey=info.verkey, kid=kid)
        
        pub_key_hex = base58.b58decode(info.verkey.encode()).hex()
            
        if kid_type == "MultiKey":
            if key_type == ED25519:
                multikey = 'z'+base58.b58encode(bytes.fromhex('ed01'+pub_key_hex)).decode()
                
            return {
                "id": kid,
                "type": kid_type,
                "controller": did,
                "publicKeyMultibase": multikey,
            }
            
        if kid_type == "JsonWebKey":
            if key_type == ED25519:
                pubkey = base64.urlsafe_b64encode(bytes.fromhex(pub_key_hex)).decode()
                
            return {
                "id": kid,
                "type": kid_type,
                "controller": did,
                "publicKeyJwk": {
                    "kty":"OKP",
                    "crv":"Ed25519",
                    "x": pubkey
                }
            }
