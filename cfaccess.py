"""Cloudflare Access JWT verification (Cf-Access-Jwt-Assertion header)."""
import os

import jwt
from jwt import PyJWKClient

TEAM_DOMAIN = os.environ.get("SM_CF_TEAM_DOMAIN", "").strip()
AUD = os.environ.get("SM_CF_AUD", "").strip()
ALLOWED_EMAILS = {e.strip().lower() for e in os.environ.get("SM_CF_ALLOWED_EMAILS", "").split(",") if e.strip()}
ENABLED = bool(TEAM_DOMAIN and AUD)

_jwks = PyJWKClient(f"https://{TEAM_DOMAIN}/cdn-cgi/access/certs", cache_keys=True, lifespan=3600) if ENABLED else None


def verify(token: str) -> dict | None:
    """Return the token's claims if it was signed by our Access team for this app, else None.
    Fails closed: any error (bad signature, expired, cert fetch failure) means reject."""
    if not ENABLED or not token or len(token) > 8192:
        return None
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=AUD,
                            issuer=f"https://{TEAM_DOMAIN}", leeway=30)
    except Exception:
        return None
    if ALLOWED_EMAILS and (claims.get("email") or "").lower() not in ALLOWED_EMAILS:
        return None
    return claims
