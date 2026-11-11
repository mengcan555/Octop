"""Password hashing: bcrypt (new) with transparent argon2id fallback.

``verify_password`` inspects the stored hash prefix and dispatches to the
matching algorithm. ``needs_rehash`` returns True for legacy argon2id hashes
so callers (e.g. login flow) can auto-upgrade on a successful match.
"""

from __future__ import annotations

import re

import bcrypt

from octop.infra.errors import ErrorCode, OctopError

_ARGON2_PREFIX = re.compile(r"^\$argon2")

MIN_PASSWORD_LENGTH = 8

# Case-insensitive denylist for change-password (and shared policy) checks.
_COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "password12",
        "password123",
        "12345678",
        "123456789",
        "qwerty123",
        "admin123",
        "welcome1",
        "letmein1",
        "changeme1",
        "octop123",
        "abc12345",
        "iloveyou1",
    }
)

def hash_password(plain: str) -> str:
    """Return a fresh bcrypt hash of *plain*."""
    if not plain:
        raise ValueError("password must not be empty")
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    """Verify *plain* against *hashed*.

    Dispatches by prefix so both legacy argon2id (``$argon2...``) and current
    bcrypt (``$2b$...`` / ``$2a$...``) hashes are accepted.
    """
    if not hashed:
        return False
    if _ARGON2_PREFIX.match(hashed):
        return _verify_argon2(plain, hashed)
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False

def needs_rehash(hashed: str) -> bool:
    """True if *hashed* is a legacy argon2id hash and should be rewritten
    as bcrypt on the next successful authentication."""
    return bool(_ARGON2_PREFIX.match(hashed))

def _verify_argon2(plain: str, hashed: str) -> bool:
    """Legacy argon2id verifier.

    Lazy import — production installs that dropped argon2-cffi will simply
    fail verification for old hashes (but the login auto-upgrade path will
    have rewritten them long before that matters).
    """
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
    except ImportError:
        return False
    try:
        return PasswordHasher().verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def validate_password_policy(password: str, *, old_password: str | None = None) -> None:
    """Raise ``OctopError`` when ``password`` is too weak or equals ``old_password``.

    Rules: at least ``MIN_PASSWORD_LENGTH`` chars, include a letter and a digit,
    not in a small common-password denylist, and not identical to the current password
    when ``old_password`` is provided.
    """
    if old_password is not None and password == old_password:
        raise OctopError(
            ErrorCode.PASSWORD_SAME_AS_OLD,
            "new password must differ from current password",
        )
    if len(password) < MIN_PASSWORD_LENGTH:
        raise OctopError(ErrorCode.PASSWORD_TOO_WEAK, "password too short")
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    if not (has_letter and has_digit):
        raise OctopError(
            ErrorCode.PASSWORD_TOO_WEAK,
            "password must include letters and digits",
        )
    if password.lower() in _COMMON_PASSWORDS:
        raise OctopError(ErrorCode.PASSWORD_TOO_WEAK, "password is too common")