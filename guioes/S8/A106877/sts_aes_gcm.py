#!/usr/bin/env python3
from multiprocessing import Pipe, Process

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_public_key,
    load_pem_private_key,
    load_pem_public_key,
)

P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B
80DC1CD1 29024E08 8A67CC74 020BBEA6 3B139B22
514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D
F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6
F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB
5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB
9ED52907 7096966D 670C354E 4ABC9804 F1746C08
CA18217C 32905E46 2E36CE3B E39E772C 180E8603
9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6
95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""

CA_CERT = "CA.crt"
ALICE_CERT = "Alice.crt"
ALICE_KEY = "Alice.key"
BOB_CERT = "Bob.crt"
BOB_KEY = "Bob.key"


def dh_parameters() -> dh.DHParameters:
    p = int(P_HEX.replace(" ", "").replace("\n", ""), 16)
    g = 2
    return dh.DHParameterNumbers(p, g).parameters()


def serialize_public_key(key) -> bytes:
    return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def deserialize_public_key(data: bytes):
    return load_der_public_key(data)


def derive_key(shared: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"sts aes gcm",
    )
    return hkdf.derive(shared)


def mkpair(x: bytes, y: bytes) -> bytes:
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y


def unpair(xy: bytes) -> tuple[bytes, bytes]:
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_private_key(path: str):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def verify_cert(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def sign(priv_key, data: bytes) -> bytes:
    return priv_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(pub_key, signature: bytes, data: bytes) -> None:
    pub_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def alice_process(conn) -> None:
    params = dh_parameters()
    alice_priv = params.generate_private_key()
    alice_pub_bytes = serialize_public_key(alice_priv.public_key())

    ca_cert = load_cert(CA_CERT)
    alice_cert = load_cert(ALICE_CERT)
    alice_key = load_private_key(ALICE_KEY)

    conn.send(alice_pub_bytes)

    payload = conn.recv()
    bob_pub_bytes, rest = unpair(payload)
    bob_sig, bob_cert_bytes = unpair(rest)
    bob_cert = x509.load_pem_x509_certificate(bob_cert_bytes)
    verify_cert(bob_cert, ca_cert)

    bob_pub = deserialize_public_key(bob_pub_bytes)
    data = bob_pub_bytes + alice_pub_bytes
    verify_signature(bob_cert.public_key(), bob_sig, data)

    data_a = alice_pub_bytes + bob_pub_bytes
    sig_a = sign(alice_key, data_a)
    cert_bytes = alice_cert.public_bytes(Encoding.PEM)
    conn.send(mkpair(sig_a, cert_bytes))

    shared = alice_priv.exchange(bob_pub)
    key = derive_key(shared)

    aesgcm = AESGCM(key)
    nonce = AESGCM.generate_key(bit_length=96)[:12]
    msg = b"Mensagem autenticada da Alice"
    ctxt = aesgcm.encrypt(nonce, msg, None)
    conn.send(mkpair(nonce, ctxt))


def bob_process(conn) -> None:
    params = dh_parameters()
    bob_priv = params.generate_private_key()
    bob_pub_bytes = serialize_public_key(bob_priv.public_key())

    ca_cert = load_cert(CA_CERT)
    bob_cert = load_cert(BOB_CERT)
    bob_key = load_private_key(BOB_KEY)

    alice_pub_bytes = conn.recv()

    data_b = bob_pub_bytes + alice_pub_bytes
    sig_b = sign(bob_key, data_b)
    cert_bytes = bob_cert.public_bytes(Encoding.PEM)
    conn.send(mkpair(bob_pub_bytes, mkpair(sig_b, cert_bytes)))

    payload = conn.recv()
    sig_a, alice_cert_bytes = unpair(payload)
    alice_cert = x509.load_pem_x509_certificate(alice_cert_bytes)
    verify_cert(alice_cert, ca_cert)

    data = alice_pub_bytes + bob_pub_bytes
    verify_signature(alice_cert.public_key(), sig_a, data)

    alice_pub = deserialize_public_key(alice_pub_bytes)
    shared = bob_priv.exchange(alice_pub)
    key = derive_key(shared)

    aesgcm = AESGCM(key)
    payload = conn.recv()
    nonce, ctxt = unpair(payload)
    msg = aesgcm.decrypt(nonce, ctxt, None)
    print("Bob recebeu:", msg.decode("utf-8", errors="replace"))


def main() -> None:
    parent_conn, child_conn = Pipe()
    p1 = Process(target=alice_process, args=(parent_conn,))
    p2 = Process(target=bob_process, args=(child_conn,))
    p1.start()
    p2.start()
    p1.join()
    p2.join()


if __name__ == "__main__":
    main()
