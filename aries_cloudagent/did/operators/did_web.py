
from ...wallet.key_type import KeyType, ED25519
import requests
import base58
from ..did_key import construct_did_key_ed25519
from ...wallet.did_method import WEB
from ...wallet.base import BaseWallet
from ...vc_api.services import (
    IssuerService,
    IssuerServiceError
)

class DidOperatorError(Exception):
    """Generic Operator Error."""


class DidWebOperator:
    """Operator for managing web dids."""

    def __init__(self, profile):
        """Initialize a new `DidWebOperator` instance.
        """
        self.profile = profile



    async def register_did(
        self,
        server: str,
        identifier: str,
        endorser: str,
        key_type: KeyType = ED25519,
    ):
        """Create, store and register a new web DID.

        Args:
            server: The server to register the did with
            identifier: The DID identifier to use
            endorser: The did of the endorser to use
            key_type: The key type to use for the DID

        Returns:
            A `DIDDocument` instance representing the created DID

        Raises:
            DidWebOperatorError: If the an error occures during did registration

        """
        server_endpoint = f'{server}/{identifier}/did.json'
        r = requests.get(server_endpoint)
        try:
            did_doc = r.json()['didDocument']
            proof_options = r.json()['proofOptions']
        except:
            raise DidOperatorError()
        did =  did_doc['id']
        didcomm_endpoint = self.profile.settings.get('default_endpoint')
        did_doc['service'] = [
            {
                    'id': f'{did}#didcomm',
                    'type': 'didcomm',
                    'serviceEndpoint': didcomm_endpoint
            }
        ] if didcomm_endpoint else []
        
        async with self.profile.session() as session:
            wallet = session.inject(BaseWallet)
        info = await wallet.create_local_did(
            method=WEB, key_type=ED25519, did=did
        )
        pub_key_hex = base58.b58decode(info.verkey.encode()).hex()
        eddsa_multikey = 'z'+base58.b58encode(bytes.fromhex('ed01'+pub_key_hex)).decode()
        
        did_doc['verificationMethod'] = [
            {
                'id': f'{did}#verkey',
                'type': 'MultiKey',
                'controller': did,
                'publicKeyMultibase': eddsa_multikey,
            }
        ]
        did_doc['authentication'] = [f'{did}#verkey']
        did_doc['assertionMethod'] = [f'{did}#verkey']
        
        proof_options['verificationMethod'] = f'{endorser}#{endorser.split(":")[-1]}'
        signed_did_doc = await IssuerService(self.profile).add_proof(
            did_doc, proof_options
        )
        r = requests.post(server_endpoint, json=signed_did_doc)
        try:
            did_doc = r.json()['didDocument']
        except:
            raise DidOperatorError()
        
        return did_doc
        
        