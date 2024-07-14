from .ed25519_signature_2020 import Ed25519Signature2020 as _Ed25519Signature2020
from .ed25519_signature_2020 import Ed25519Signature2020
from .eddsa_jcs_2022 import EddsaJcs2022
from .eddsa_rdfc_2022 import EddsaRdfc2022
from ....wallet.key_type import ED25519


CRYPTOSUITES = {
    "Ed25519Signature2020": {"key_type": ED25519, "suite": Ed25519Signature2020},
    "eddsa-jcs-2022": {"key_type": ED25519, "suite": EddsaJcs2022},
    "eddsa-rdfc-2022": {"key_type": ED25519, "suite": EddsaRdfc2022},
}


__all__ = [
    "_Ed25519Signature2020",
    "Ed25519Signature2020",
    "EddsaJcs2022",
    "EddsaRdfc2022",
]
