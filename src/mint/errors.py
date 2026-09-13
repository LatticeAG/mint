"""Mint error model.

Every API error is {"error": {code, message, retryable, details}}.
CLI exit codes (spec §8.6):
  0 ok, 2 invalid input/config, 3 auth/role, 4 conflict/deadline,
  5 insufficient funds, 6 unavailable, 7 verification failure,
  8 private evidence unavailable.
"""

from __future__ import annotations


class MintError(Exception):
    def __init__(
        self,
        http: int,
        code: str,
        message: str,
        retryable: bool = False,
        details: dict | None = None,
    ):
        super().__init__(f"{code}: {message}")
        self.http = http
        self.code = code
        self.message = message
        self.retryable = retryable
        self.details = details or {}

    def body(self) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
                "details": self.details,
            }
        }

    @property
    def exit_code(self) -> int:
        return http_to_exit(self.http, self.code)


def http_to_exit(http: int, code: str) -> int:
    if http == 400:
        return 2
    if http in (401, 403):
        return 3
    if http == 404:
        return 2
    if http == 409:
        return 4
    if http == 422:
        return 5 if code == "INSUFFICIENT_FUNDS" else 2
    if http == 429:
        return 6
    if http in (500, 503):
        return 6
    return 2


def malformed(msg: str, details: dict | None = None) -> MintError:
    return MintError(400, "MALFORMED", msg, False, details or {})


def unauthorized(msg: str = "Request authentication failed") -> MintError:
    return MintError(401, "BAD_SIGNATURE", msg, False, {})


def forbidden(msg: str, details: dict | None = None) -> MintError:
    return MintError(403, "ROLE_FORBIDDEN", msg, False, details or {})


def not_found(msg: str, details: dict | None = None) -> MintError:
    return MintError(404, "NOT_FOUND", msg, False, details or {})


def conflict(code: str, msg: str, details: dict | None = None) -> MintError:
    return MintError(409, code, msg, True, details or {})


def policy(code: str, msg: str, details: dict | None = None) -> MintError:
    return MintError(422, code, msg, False, details or {})


def insufficient(required: int, available: int) -> MintError:
    return MintError(
        422,
        "INSUFFICIENT_FUNDS",
        f"requires {required} SIMUSD",
        False,
        {"required": str(required), "available": str(available)},
    )


def rate_limited(msg: str, limit: int, retry_after: int) -> MintError:
    return MintError(
        429, "RATE_LIMITED", msg, True,
        {"limit": limit, "retry_after_seconds": retry_after},
    )


def unavailable(msg: str, details: dict | None = None) -> MintError:
    return MintError(503, "CHECKPOINT_UNAVAILABLE", msg, True, details or {})


class NotImplementedSurface(Exception):
    """A hosted/paid/zone-gated surface that is deliberately out of OSS scope.

    Always carries the spec-grounded reason the surface is unavailable.
    """

    def __init__(self, surface: str, reason: str):
        super().__init__(f"{surface}: {reason}")
        self.surface = surface
        self.reason = reason
