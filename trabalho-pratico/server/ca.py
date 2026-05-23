import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def issue_certificate(uid: str, pub_key_b64: str,
                      signing_key: Ed25519PrivateKey) -> tuple[str, str]:
    """
    Emite um certificado digital associando uid ↔ pub_key, assinado com Ed25519.
    Devolve (cert_json, sig_b64).
    cert_json é o JSON canónico (chaves ordenadas, sem espaços) — é o que se assina.
    """
    cert = {
        "issued_at": int(time.time()),
        "pub_key":   pub_key_b64,
        "uid":       uid,
    }
    cert_json = json.dumps(cert, sort_keys=True, separators=(",", ":"))
    sig       = signing_key.sign(cert_json.encode())
    return cert_json, base64.b64encode(sig).decode()
