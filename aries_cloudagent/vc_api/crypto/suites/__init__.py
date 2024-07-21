from ....wallet.key_type import ED25519, X25519
from .ed25519_signature_2020 import Ed25519Signature2020
from .eddsa_jcs_2022 import EddsaJcs2022
from .eddsa_rdfc_2022 import EddsaRdfc2022

# from .anoncreds_2023 import AnonCreds2023


CRYPTOSUITES = {
    "Ed25519Signature2020": {"key_type": ED25519, "suite": Ed25519Signature2020},
    "eddsa-jcs-2022": {"key_type": ED25519, "suite": EddsaJcs2022},
    "eddsa-rdfc-2022": {"key_type": ED25519, "suite": EddsaRdfc2022},
    # "anoncreds-2023": {"key_type": None, "suite": AnonCreds2023},
    # "ecdsa-jcs-2019": {"key_type": X25519, "suite": EcdsaJcs2022},
    # "ecdsa-rdfc-2019": {"key_type": X25519, "suite": EcdsaRdfc2022},
}


__all__ = [
    "Ed25519Signature2020",
    "EddsaJcs2022",
    "EddsaRdfc2022",
    # "AnonCreds2023"
]
