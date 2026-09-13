"""Cryptographic primitives: Ed25519, X25519+HKDF+ChaCha20-Poly1305 wraps.

Wrap envelope (spec §2.6): canonical object
  {ephemeral_pub, nonce, ciphertext}
where the shared key is X25519(ephemeral_sk, recipient_pk) -> HKDF-SHA256
-> ChaCha20-Poly1305.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import malformed
from .jsonutil import jcs_text, sha256_hex

_WRAP_INFO = b"mint.keywrap.v1"
_CHUNK_INFO = b"mint.deliverable.chunk.v1"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    if not isinstance(text, str) or "=" in text:
        raise malformed("signature must be unpadded base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * ((-len(text)) % 4))
    except Exception as e:
        raise malformed("invalid base64url") from e


def ed25519_keypair() -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ), pk


def ed25519_sign(secret: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(secret).sign(message)


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def x25519_keypair() -> tuple[bytes, bytes]:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ), pk


def _x25519_shared(secret: bytes, public: bytes) -> bytes:
    sk = X25519PrivateKey.from_private_bytes(secret)
    pk = X25519PublicKey.from_public_bytes(public)
    return sk.exchange(pk)


def _hkdf(shared: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=None, info=info
    ).derive(shared)


def wrap_key(tk: bytes, recipient_pub: bytes) -> dict:
    """Wrap a deliverable key TK to a recipient X25519 public key.

    Returns the canonical envelope object {ephemeral_pub, nonce, ciphertext}
    with hex fields.
    """
    eph_sk, eph_pk = x25519_keypair()
    shared = _x25519_shared(eph_sk, recipient_pub)
    key = _hkdf(shared, _WRAP_INFO)
    nonce = os.urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, tk, None)
    return {
        "ephemeral_pub": eph_pk.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    }


def unwrap_key(envelope: dict, recipient_secret: bytes) -> bytes:
    """Unwrap; raises ValueError on any decryption or shape failure."""
    try:
        eph_pub = bytes.fromhex(envelope["ephemeral_pub"])
        nonce = bytes.fromhex(envelope["nonce"])
        ct = bytes.fromhex(envelope["ciphertext"])
        if len(eph_pub) != 32 or len(nonce) != 12 or len(ct) < 16:
            raise ValueError("malformed envelope")
        shared = _x25519_shared(recipient_secret, eph_pub)
        key = _hkdf(shared, _WRAP_INFO)
        return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    except (KeyError, ValueError) as e:
        raise ValueError("envelope unwrap failed") from e
    except Exception as e:  # InvalidTag etc.
        raise ValueError("envelope unwrap failed") from e


def tk_commitment(tk: bytes) -> str:
    return sha256_hex(b"mint.tk.v1\x00" + tk)


def seal_chunk(tk: bytes, plaintext: bytes) -> bytes:
    """Encrypt one deliverable chunk under TK: nonce || ciphertext."""
    key = _hkdf(tk, _CHUNK_INFO)
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def open_chunk(tk: bytes, blob: bytes) -> bytes:
    key = _hkdf(tk, _CHUNK_INFO)
    nonce, ct = blob[:12], blob[12:]
    if len(nonce) != 12:
        raise ValueError("malformed chunk")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise ValueError("chunk decrypt failed") from e


def deliverable_commitment(salt_hex: str, plaintext_digests: list[str]) -> str:
    """SHA256("mint.deliverable.v1\0" || salt || JCS(plaintext_chunk_digests))."""
    return sha256_hex(
        b"mint.deliverable.v1\x00"
        + bytes.fromhex(salt_hex)
        + jcs_text(plaintext_digests).encode("utf-8")
    )


def random_hex(nbytes: int) -> str:
    return os.urandom(nbytes).hex()


def seat_id(task_id: str, index: int, blinding: str) -> str:
    """Sealed per-task seat identifier, unlinkable to its principal group."""
    return "seat-" + sha256_hex(
        b"mint.seat.id.v1\x00" + jcs_text(
            {"blinding": blinding, "index": index, "task_id": task_id}
        ).encode()
    )[:24]
