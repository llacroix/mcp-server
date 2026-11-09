"""OAuth 2.0 Resource Server authentication (JWT/JWKS and RFC 7662 Introspection)."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import anyio.to_thread
import httpx
import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from mcp_server.session import RedisSessionStore, current_user_sub

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _parse_scopes(claims: dict[str, Any]) -> list[str]:
    """Extract OAuth 2.0 scopes from standard JWT/introspection claims."""
    raw_scope = claims.get("scope")
    if isinstance(raw_scope, str):
        return [s for s in raw_scope.split() if s]
    if isinstance(raw_scope, list):
        return [str(s) for s in raw_scope if s]

    raw_scp = claims.get("scp")
    if isinstance(raw_scp, str):
        return [s for s in raw_scp.split() if s]
    if isinstance(raw_scp, list):
        return [str(s) for s in raw_scp if s]

    return []


def _resolve_resource(
    claims: dict[str, Any],
    expected_resource: str | None,
) -> str | None:
    """Resolve the RFC 8707 resource / audience from token claims."""
    resource = claims.get("resource") or claims.get("aud")
    if isinstance(resource, str):
        return resource
    if isinstance(resource, list):
        if expected_resource:
            normalized_expected = expected_resource.removesuffix("/")
            for item in resource:
                if str(item).removesuffix("/") == normalized_expected:
                    return str(item)
        return str(resource[0]) if resource else None
    return None


class JWTTokenVerifier(TokenVerifier):
    """Verify OAuth 2.0 Bearer JWTs via a JWKS endpoint or static secret/public key."""

    def __init__(
        self,
        *,
        issuer_url: str,
        resource_server_url: str | None = None,
        audience: str | None = None,
        jwks_url: str | None = None,
        secret_or_key: str | None = None,
        algorithms: list[str] | None = None,
        session_store: RedisSessionStore | None = None,
    ) -> None:
        if not jwks_url and not secret_or_key:
            raise ValueError("Either jwks_url or secret_or_key must be provided for JWTTokenVerifier")

        self.issuer_url = issuer_url
        base_issuer = issuer_url.removesuffix("/")
        self._accepted_issuers = list({issuer_url, base_issuer, f"{base_issuer}/"}) if issuer_url else None
        self.resource_server_url = resource_server_url
        self.session_store = session_store

        aud_list: list[str] = []
        if audience and audience.strip():
            aud_list.append(audience.strip())
        if resource_server_url and resource_server_url.strip():
            raw = resource_server_url.strip()
            base_res = raw.removesuffix("/")
            aud_list.extend([raw, base_res, f"{base_res}/"])
            parsed = urlparse(raw)
            if parsed.scheme and parsed.netloc:
                origin = f"{parsed.scheme}://{parsed.netloc}"
                aud_list.extend([origin, f"{origin}/"])
        self.audience: list[str] | None = list(dict.fromkeys(aud_list)) if aud_list else None

        self.secret_or_key = secret_or_key
        self.algorithms = algorithms or (["RS256", "ES256"] if jwks_url else ["HS256"])
        self._jwk_client = PyJWKClient(jwks_url) if jwks_url else None
        logger.info(
            "[JWTTokenVerifier] Initialized: issuer_url=%s, accepted_issuers=%s, audience=%s, jwks_url=%s, algorithms=%s",
            self.issuer_url,
            self._accepted_issuers,
            self.audience,
            jwks_url,
            self.algorithms,
        )

    def _decode_sync(self, token: str) -> dict[str, Any]:
        signing_key: Any = self.secret_or_key
        if self._jwk_client is not None:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            alg = unverified_header.get("alg")
            logger.info("[JWTTokenVerifier] Resolving JWKS signing key for kid=%s, alg=%s from %s", kid, alg, self._jwk_client.uri)
            try:
                signing_key = self._jwk_client.get_signing_key_from_jwt(token).key
                logger.info("[JWTTokenVerifier] Successfully resolved JWKS signing key for kid=%s", kid)
            except Exception as exc:
                logger.error("[JWTTokenVerifier] Failed to resolve signing key from JWKS for kid=%s: %s", kid, exc, exc_info=exc)
                raise

        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": bool(self._accepted_issuers),
            "verify_aud": bool(self.audience),
        }
        logger.info(
            "[JWTTokenVerifier] Running jwt.decode with algorithms=%s, issuers=%s, audience=%s, options=%s",
            self.algorithms,
            self._accepted_issuers,
            self.audience,
            options,
        )
        try:
            decoded = jwt.decode(
                token,
                signing_key,
                algorithms=self.algorithms,
                issuer=self._accepted_issuers,
                audience=self.audience,
                options=options,
            )
            logger.info("[JWTTokenVerifier] Successfully decoded and validated JWT: claims=%s", decoded)
            return decoded
        except jwt.ExpiredSignatureError as exc:
            logger.warning("[JWTTokenVerifier] Token expired: %s", exc, exc_info=exc)
            raise
        except jwt.InvalidAudienceError as exc:
            logger.warning("[JWTTokenVerifier] Invalid audience (expected %s): %s", self.audience, exc, exc_info=exc)
            raise
        except jwt.InvalidIssuerError as exc:
            logger.warning("[JWTTokenVerifier] Invalid issuer (expected one of %s): %s", self._accepted_issuers, exc, exc_info=exc)
            raise
        except jwt.InvalidSignatureError as exc:
            logger.warning("[JWTTokenVerifier] Invalid signature: %s", exc, exc_info=exc)
            raise
        except jwt.PyJWTError as exc:
            logger.warning("[JWTTokenVerifier] PyJWT error during decode: %s", exc, exc_info=exc)
            raise
        except Exception as exc:
            logger.error("[JWTTokenVerifier] Unexpected error during decode: %s", exc, exc_info=exc)
            raise

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a JWT Bearer token and convert it to an MCP AccessToken."""
        logger.info("[JWTTokenVerifier] verify_token called: token_length=%d", len(token))
        try:
            unverified_header = jwt.get_unverified_header(token)
            unverified_claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            logger.info(
                "[JWTTokenVerifier] Diagnostic token inspection -> Header: %s | Claims: %s | Accepted issuers: %s | Expected aud: %s",
                unverified_header,
                unverified_claims,
                self._accepted_issuers,
                self.audience,
            )
        except Exception as exc:
            logger.warning("[JWTTokenVerifier] Failed to parse unverified JWT for debugging: %s", exc, exc_info=exc)

        try:
            claims = await anyio.to_thread.run_sync(self._decode_sync, token)
        except Exception as exc:
            logger.warning("[JWTTokenVerifier] Token verification failed: %s", exc, exc_info=exc)
            return None

        client_id = str(claims.get("client_id") or claims.get("azp") or claims.get("sub") or "unknown")
        subject = str(claims["sub"]) if "sub" in claims and claims["sub"] is not None else None
        expires_at = int(claims["exp"]) if "exp" in claims and claims["exp"] is not None else None
        scopes = _parse_scopes(claims)
        resource = _resolve_resource(claims, self.resource_server_url)

        logger.info(
            "[JWTTokenVerifier] JWT verification succeeded! Principal: client_id=%s, subject=%s, scopes=%s, resource=%s",
            client_id,
            subject,
            scopes,
            resource,
        )

        if self.session_store and subject:
            try:
                await self.session_store.create_or_update_session(
                    sub=subject,
                    claims=claims,
                )
            except Exception as exc:
                logger.error("[JWTTokenVerifier] Failed to update Redis session for sub %s: %s", subject, exc, exc_info=exc)

        if subject:
            current_user_sub.set(subject)

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=resource,
            subject=subject,
            claims=claims,
        )


class IntrospectionTokenVerifier(TokenVerifier):
    """Verify OAuth 2.0 Bearer tokens using RFC 7662 Token Introspection."""

    def __init__(
        self,
        *,
        introspection_url: str,
        issuer_url: str | None = None,
        resource_server_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        timeout: float = 5.0,
        session_store: RedisSessionStore | None = None,
    ) -> None:
        self.introspection_url = introspection_url
        self.issuer_url = issuer_url.removesuffix("/") if issuer_url else None
        self.resource_server_url = resource_server_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.session_store = session_store
        logger.info(
            "[IntrospectionTokenVerifier] Initialized: introspection_url=%s, issuer_url=%s, client_id=%s",
            introspection_url,
            self.issuer_url,
            client_id,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        """Introspect an opaque or JWT Bearer token via RFC 7662."""
        logger.info("[IntrospectionTokenVerifier] verify_token called: token_length=%d", len(token))
        auth = (self.client_id, self.client_secret or "") if self.client_id else None
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                logger.info(
                    "[IntrospectionTokenVerifier] Sending POST to %s (auth=%s)",
                    self.introspection_url,
                    "basic_auth" if auth else "none",
                )
                response = await client.post(
                    self.introspection_url,
                    data={"token": token, "token_type_hint": "access_token"},
                    auth=auth,
                    headers={"Accept": "application/json"},
                )
                logger.info("[IntrospectionTokenVerifier] Response status %d: %s", response.status_code, response.text[:200])
                if response.status_code != 200:
                    logger.warning("Token introspection returned HTTP %s", response.status_code)
                    return None
                data: dict[str, Any] = response.json()
        except Exception as exc:
            logger.warning("Token introspection request failed: %s", exc, exc_info=exc)
            return None

        if not data.get("active", False):
            logger.warning("[IntrospectionTokenVerifier] Token is not active (data=%s)", data)
            return None

        exp = data.get("exp")
        expires_at = int(exp) if exp is not None else None
        if expires_at and expires_at < int(time.time()):
            logger.warning("Introspected token is expired (exp=%s)", expires_at)
            return None

        if self.issuer_url and data.get("iss"):
            token_iss = str(data["iss"]).removesuffix("/")
            if token_iss != self.issuer_url:
                logger.warning("Token issuer %r does not match expected %r", data.get("iss"), self.issuer_url)
                return None

        client_id = str(data.get("client_id") or data.get("sub") or "unknown")
        subject = str(data["sub"]) if "sub" in data and data["sub"] is not None else None
        scopes = _parse_scopes(data)
        resource = _resolve_resource(data, self.resource_server_url)

        logger.info(
            "[IntrospectionTokenVerifier] Token active! Principal: client_id=%s, subject=%s, scopes=%s, resource=%s",
            client_id,
            subject,
            scopes,
            resource,
        )

        if self.session_store and subject:
            try:
                await self.session_store.create_or_update_session(
                    sub=subject,
                    claims=data,
                )
            except Exception as exc:
                logger.error("[IntrospectionTokenVerifier] Failed to update Redis session for sub %s: %s", subject, exc, exc_info=exc)

        if subject:
            current_user_sub.set(subject)

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=resource,
            subject=subject,
            claims=data,
        )


def create_auth_settings(
    *,
    issuer_url: str,
    resource_server_url: str,
    required_scopes: list[str] | None = None,
    validate_token_resource: bool = False,
) -> AuthSettings:
    """Create MCP AuthSettings for an OAuth 2.0 Resource Server."""
    return AuthSettings(
        issuer_url=AnyHttpUrl(issuer_url),
        resource_server_url=AnyHttpUrl(resource_server_url),
        required_scopes=required_scopes or None,
        validate_token_resource=validate_token_resource,
    )


def build_transport_security(
    *,
    host: str,
    resource_server_url: str | None = None,
    allowed_hosts: tuple[str, ...] = (),
    allowed_origins: tuple[str, ...] = (),
    disable_dns_rebinding_protection: bool = False,
) -> TransportSecuritySettings:
    """Build TransportSecuritySettings aware of reverse proxies like Traefik."""
    if disable_dns_rebinding_protection:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)

    hosts: list[str] = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    origins: list[str] = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]

    if host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        hosts.extend([host, f"{host}:*"])

    if resource_server_url:
        parsed = urlparse(resource_server_url)
        if parsed.netloc:
            hosts.append(parsed.netloc)
            if ":" not in parsed.netloc:
                hosts.append(f"{parsed.netloc}:*")
        if parsed.scheme and parsed.netloc:
            origins.append(f"{parsed.scheme}://{parsed.netloc}")

    for extra_host in allowed_hosts:
        if extra_host not in hosts:
            hosts.append(extra_host)

    for extra_origin in allowed_origins:
        if extra_origin not in origins:
            origins.append(extra_origin)

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=origins,
    )
