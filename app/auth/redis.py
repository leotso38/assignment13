# app/auth/redis.py
"""
Simple in-memory blacklist for JWT JTI values.
Replaces aioredis (which breaks on Python 3.12).
"""

from typing import Set

_blacklisted: Set[str] = set()

async def add_to_blacklist(jti: str, exp: int | None = None) -> None:
    """Add a token's JTI to the blacklist."""
    _blacklisted.add(jti)

async def is_blacklisted(jti: str) -> bool:
    """Return True if the token's JTI is blacklisted."""
    return jti in _blacklisted
