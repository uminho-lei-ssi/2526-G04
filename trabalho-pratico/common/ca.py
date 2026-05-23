import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_certificate(cert_json: str, sig_b64: str,
                        signing_pub_bytes: bytes) -> dict:
    """
    Verifica a assinatura Ed25519 do servidor sobre cert_json.
    Devolve o certificado como dict se válido.
    Lança ValueError se a assinatura ou o JSON forem inválidos.
    """
    try:
        sig = base64.b64decode(sig_b64)
    except Exception as e:
        raise ValueError(f"Assinatura inválida (base64): {e}")

    pub = Ed25519PublicKey.from_public_bytes(signing_pub_bytes)
    try:
        pub.verify(sig, cert_json.encode())
    except InvalidSignature:
        raise ValueError(
            "Certificado inválido: assinatura do servidor não verificada. "
            "Possível ataque Man-in-the-Middle."
        )

    try:
        return json.loads(cert_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Certificado inválido (JSON): {e}")
