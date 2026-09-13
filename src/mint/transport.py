"""Signed transport contract (spec §8.1).

Signed object:
  {v:1, network, method, target, actor, key_epoch, nonce, issued_at,
   expires, body_hash, idempotency_key}
Message: "mint.http.request.v1" || 0x00 || JCS(signed_object)
Signature: Ed25519, unpadded base64url in the Mint-Signature header.
"""

from __future__ import annotations

from .crypto import b64u, ed25519_sign, ed25519_verify, unb64u
from .errors import malformed, unauthorized
from .jsonutil import jcs, sha256_hex
from .timeutil import parse_ts

SIGN_DOMAIN = b"mint.http.request.v1\x00"

REQUIRED_HEADERS = (
    "Mint-Actor", "Mint-Key-Epoch", "Mint-Nonce", "Mint-Issued-At",
    "Mint-Expires", "Mint-Signature", "Idempotency-Key",
)


def body_hash(body_bytes: bytes) -> str:
    return sha256_hex(body_bytes)


def signed_object(network: str, method: str, target: str, actor: str,
                  key_epoch: int, nonce: str, issued_at: str, expires: str,
                  body_b64_hash: str, idem_key: str) -> dict:
    return {
        "v": 1, "network": network, "method": method, "target": target,
        "actor": actor, "key_epoch": key_epoch, "nonce": nonce,
        "issued_at": issued_at, "expires": expires,
        "body_hash": body_b64_hash, "idempotency_key": idem_key,
    }


def signing_message(obj: dict) -> bytes:
    return SIGN_DOMAIN + jcs(obj)


def sign_request(secret: bytes, network: str, method: str, target: str,
                 actor: str, key_epoch: int, nonce: str, issued_at: str,
                 expires: str, body_bytes: bytes, idem_key: str) -> dict:
    """Produce the header map for a signed request."""
    obj = signed_object(network, method, target, actor, key_epoch, nonce,
                        issued_at, expires, body_hash(body_bytes), idem_key)
    sig = b64u(ed25519_sign(secret, signing_message(obj)))
    return {
        "Mint-Actor": actor,
        "Mint-Key-Epoch": str(key_epoch),
        "Mint-Nonce": nonce,
        "Mint-Issued-At": issued_at,
        "Mint-Expires": expires,
        "Mint-Signature": sig,
        "Idempotency-Key": idem_key,
    }


def verify_request(headers: dict, body_bytes: bytes, network: str,
                   method: str, target: str, public_key: bytes) -> dict:
    """Verify signature and return the signed object. Raises on failure."""
    try:
        obj = signed_object(
            network, method, target,
            headers["Mint-Actor"], int(headers["Mint-Key-Epoch"]),
            headers["Mint-Nonce"], headers["Mint-Issued-At"],
            headers["Mint-Expires"], body_hash(body_bytes),
            headers["Idempotency-Key"],
        )
    except (KeyError, ValueError) as e:
        raise malformed(f"missing/invalid transport header: {e}") from e
    sig = unb64u(headers.get("Mint-Signature", ""))
    if len(sig) != 64 or not public_key or not ed25519_verify(
            public_key, sig, signing_message(obj)):
        raise unauthorized()
    return obj


def check_time_bounds(obj: dict, now_ms: int) -> None:
    """issued_at <= now+30s; issued_at < expires <= issued_at+300s;
    now < expires <= now+300s."""
    issued = parse_ts(obj["issued_at"], "issued_at")
    expires = parse_ts(obj["expires"], "expires")
    skew = 30_000
    window = 300_000
    if not (issued <= now_ms + skew):
        raise unauthorized("issued_at is in the future")
    if not (issued < expires <= issued + window):
        raise unauthorized("expires outside 300s window")
    if not (now_ms < expires <= now_ms + window):
        raise unauthorized("request expired or expires beyond window")
