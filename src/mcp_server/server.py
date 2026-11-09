"""Minimal MCP server with OAuth 2.0 Resource Server auth, Redis sessions, and Google OAuth binding."""

from __future__ import annotations

import logging
import os
from typing import Literal

import anyio
import click
import jwt
import uvicorn
from dotenv import load_dotenv
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from redis.asyncio import Redis
from starlette.middleware.cors import CORSMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_server.auth import (
    IntrospectionTokenVerifier,
    JWTTokenVerifier,
    build_transport_security,
    create_auth_settings,
)
from mcp_server.event_store import RedisEventStore
from mcp_server.routes import register_routes
from mcp_server.session import RedisSessionStore, current_user_sub
from mcp_server.tools import register_tools

load_dotenv()

logger = logging.getLogger(__name__)

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def _clean_tuple(values: tuple[str, ...]) -> tuple[str, ...]:
    """Filter out empty strings when Click reads empty env vars for multiple=True options."""
    return tuple(v.strip() for v in values if v and v.strip())


class RequestLoggingMiddleware:
    """ASGI middleware to log inbound requests and propagate authenticated user sub to contextvars."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("latin1", errors="replace")
            client_ip = scope.get("client", ("unknown", 0))[0]
            method = scope.get("method", "")
            path = scope.get("path", "")

            sub_to_set: str | None = None
            if not auth_header:
                logger.debug(
                    "Inbound %s %s from %s: NO Authorization header present",
                    method,
                    path,
                    client_ip,
                )
            else:
                auth_type = auth_header.split()[0] if " " in auth_header else auth_header[:10]
                logger.info(
                    "Inbound %s %s from %s: Authorization header present (type=%s, len=%d)",
                    method,
                    path,
                    client_ip,
                    auth_type,
                    len(auth_header),
                )
                if auth_header.lower().startswith("bearer "):
                    try:
                        token = auth_header[7:].strip()
                        unverified = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
                        if "sub" in unverified and unverified["sub"]:
                            sub_to_set = str(unverified["sub"])
                    except Exception as exc:
                        logger.debug("Failed to decode token for sub logging: %s", exc, exc_info=exc)

            if not sub_to_set:
                cookie_header = headers.get(b"cookie", b"").decode("latin1", errors="replace")
                if "mcp_sub=" in cookie_header:
                    for part in cookie_header.split(";"):
                        part = part.strip()
                        if part.startswith("mcp_sub="):
                            sub_to_set = part.split("=", 1)[1].strip()
                            break

            if sub_to_set:
                current_user_sub.set(sub_to_set)

        await self.app(scope, receive, send)


def create_server(
    *,
    auth: AuthSettings | None = None,
    token_verifier: TokenVerifier | None = None,
    redis_client: Redis | None = None,
    session_store: RedisSessionStore | None = None,
    base_url: str | None = None,
    log_level: LogLevel = "INFO",
    oauth_client_id: str | None = None,
    oauth_client_secret: str | None = None,
    oauth_audience: str | None = None,
    http_oauth_issuer_url: str | None = None,
    http_oauth_client_id: str | None = None,
    http_oauth_client_secret: str | None = None,
    http_oauth_audience: str | None = None,
    google_client_id: str | None = None,
    google_client_secret: str | None = None,
    google_oauth_scopes: str | None = None,
) -> MCPServer:
    """Create and configure a new MCPServer instance with auth, sessions, tools, and custom routes."""
    mcp = MCPServer(
        name="mcp-server",
        version="0.1.0",
        instructions="Minimal starter MCP server exposing sample tools, resources, and prompts.",
        auth=auth,
        token_verifier=token_verifier,
        log_level=log_level,
    )

    register_tools(
        mcp,
        redis_client=redis_client,
        base_url=base_url,
        session_store=session_store,
    )

    register_routes(
        mcp,
        auth=auth,
        redis_client=redis_client,
        session_store=session_store,
        base_url=base_url,
        oauth_client_id=oauth_client_id,
        oauth_client_secret=oauth_client_secret,
        oauth_audience=oauth_audience,
        http_oauth_issuer_url=http_oauth_issuer_url,
        http_oauth_client_id=http_oauth_client_id,
        http_oauth_client_secret=http_oauth_client_secret,
        http_oauth_audience=http_oauth_audience,
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_oauth_scopes=google_oauth_scopes,
    )

    @mcp.resource("config://app")
    def get_app_config() -> str:
        """Return static application configuration."""
        return '{"name": "mcp-server", "version": "0.1.0", "status": "ok"}'

    @mcp.resource("greeting://{name}")
    def get_greeting(name: str) -> str:
        """Return a personalized greeting resource."""
        return f"Hello, {name}! Welcome to the MCP server."

    @mcp.prompt()
    def review_code(code: str, language: str = "python") -> str:
        """Generate a prompt asking the assistant to review a code snippet."""
        return (
            f"Please review the following {language} code for bugs, readability, "
            f"and best practices:\n\n```{language}\n{code}\n```"
        )

    return mcp


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-t",
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"], case_sensitive=False),
    default="stdio",
    envvar="MCP_TRANSPORT",
    show_default=True,
    help="Transport protocol to use.",
)
@click.option(
    "--host",
    default="127.0.0.1",
    envvar="MCP_HOST",
    show_default=True,
    help="Host to bind for HTTP/SSE transports (use 0.0.0.0 behind Traefik/Docker).",
)
@click.option(
    "-p",
    "--port",
    type=int,
    default=8000,
    envvar="MCP_PORT",
    show_default=True,
    help="Port to bind for HTTP/SSE transports.",
)
@click.option(
    "--proxy-headers/--no-proxy-headers",
    default=True,
    envvar="MCP_PROXY_HEADERS",
    show_default=True,
    help="Trust X-Forwarded-Proto and X-Forwarded-For headers from a reverse proxy (e.g. Traefik).",
)
@click.option(
    "--forwarded-allow-ips",
    default="*",
    envvar="MCP_FORWARDED_ALLOW_IPS",
    show_default=True,
    help="Comma-separated IPs allowed to set X-Forwarded-* headers.",
)
@click.option(
    "--allowed-host",
    "allowed_hosts",
    multiple=True,
    envvar="MCP_ALLOWED_HOSTS",
    help="Additional allowed Host header values for DNS rebinding protection.",
)
@click.option(
    "--allowed-origin",
    "allowed_origins",
    multiple=True,
    envvar="MCP_ALLOWED_ORIGINS",
    help="Additional allowed Origin header values for DNS rebinding protection.",
)
@click.option(
    "--disable-dns-rebinding-protection",
    is_flag=True,
    default=False,
    envvar="MCP_DISABLE_DNS_REBINDING_PROTECTION",
    help="Disable Host/Origin DNS rebinding checks (when enforced upstream by Traefik).",
)
@click.option(
    "--redis-url",
    envvar="REDIS_URL",
    help="Redis connection URL (e.g. redis://redis:6379/0) to enable resumable session event store.",
)
@click.option(
    "--oauth-issuer-url",
    envvar="MCP_OAUTH_ISSUER_URL",
    help="OAuth 2.0 Authorization Server issuer URL (enables OAuth2 authentication for Gemini MCP).",
)
@click.option(
    "--resource-server-url",
    envvar="MCP_RESOURCE_SERVER_URL",
    help="Public URL of this MCP server behind the proxy (e.g. https://mcp.example.com).",
)
@click.option(
    "--oauth-jwks-url",
    envvar="MCP_OAUTH_JWKS_URL",
    help="JWKS endpoint URL for verifying JWT Bearer tokens.",
)
@click.option(
    "--oauth-jwt-secret",
    envvar="MCP_OAUTH_JWT_SECRET",
    help="Shared secret or PEM public key for verifying JWT Bearer tokens.",
)
@click.option(
    "--oauth-jwt-algorithm",
    "oauth_jwt_algorithms",
    multiple=True,
    envvar="MCP_OAUTH_JWT_ALGORITHMS",
    help="Allowed JWT signing algorithms (defaults to RS256/ES256 for JWKS, HS256 for secret).",
)
@click.option(
    "--oauth-audience",
    envvar="MCP_OAUTH_AUDIENCE",
    help="Expected JWT audience ('aud') claim (defaults to --resource-server-url if set).",
)
@click.option(
    "--oauth-introspection-url",
    envvar="MCP_OAUTH_INTROSPECTION_URL",
    help="RFC 7662 OAuth 2.0 Token Introspection endpoint URL.",
)
@click.option(
    "--oauth-client-id",
    envvar="MCP_OAUTH_CLIENT_ID",
    help="Client ID for authenticating to the OAuth 2.0 introspection endpoint.",
)
@click.option(
    "--oauth-client-secret",
    envvar="MCP_OAUTH_CLIENT_SECRET",
    help="Client secret for authenticating to the OAuth 2.0 introspection endpoint.",
)
@click.option(
    "--oauth-required-scope",
    "oauth_required_scopes",
    multiple=True,
    envvar="MCP_OAUTH_REQUIRED_SCOPES",
    help="Scope required on incoming Bearer tokens (may be specified multiple times).",
)
@click.option(
    "--validate-token-resource/--no-validate-token-resource",
    default=False,
    envvar="MCP_VALIDATE_TOKEN_RESOURCE",
    show_default=True,
    help="Enforce RFC 8707 token resource matching against --resource-server-url.",
)
@click.option(
    "--http-oauth-issuer-url",
    envvar="MCP_HTTP_OAUTH_ISSUER_URL",
    help="OAuth 2.0 Authorization Server issuer URL for browser HTTP login (Authentik).",
)
@click.option(
    "--http-oauth-client-id",
    envvar="MCP_HTTP_OAUTH_CLIENT_ID",
    help="Client ID for browser HTTP OAuth 2.0 authorization flow.",
)
@click.option(
    "--http-oauth-client-secret",
    envvar="MCP_HTTP_OAUTH_CLIENT_SECRET",
    help="Client secret for browser HTTP OAuth 2.0 authorization flow.",
)
@click.option(
    "--http-oauth-audience",
    envvar="MCP_HTTP_OAUTH_AUDIENCE",
    help="Expected audience for browser HTTP tokens.",
)
@click.option(
    "--google-client-id",
    envvar="GOOGLE_CLIENT_ID",
    help="Google OAuth 2.0 Client ID for Gemini API Bearer token authorization.",
)
@click.option(
    "--google-client-secret",
    envvar=["GOOGLE_CLIENT_SECRET_ID", "GOOGLE_CLIENT_SECRET"],
    help="Google OAuth 2.0 Client Secret for Gemini API Bearer token authorization.",
)
@click.option(
    "--google-oauth-scopes",
    envvar="GOOGLE_OAUTH_SCOPES",
    help="Google OAuth scopes to request during authorization.",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], case_sensitive=False),
    default="INFO",
    envvar="MCP_LOG_LEVEL",
    show_default=True,
    help="Server logging level.",
)
@click.version_option(version="0.1.0", prog_name="mcp-server")
def main(
    transport: Literal["stdio", "sse", "streamable-http"],
    host: str,
    port: int,
    proxy_headers: bool,
    forwarded_allow_ips: str,
    allowed_hosts: tuple[str, ...],
    allowed_origins: tuple[str, ...],
    disable_dns_rebinding_protection: bool,
    redis_url: str | None,
    oauth_issuer_url: str | None,
    resource_server_url: str | None,
    oauth_jwks_url: str | None,
    oauth_jwt_secret: str | None,
    oauth_jwt_algorithms: tuple[str, ...],
    oauth_audience: str | None,
    oauth_introspection_url: str | None,
    oauth_client_id: str | None,
    oauth_client_secret: str | None,
    oauth_required_scopes: tuple[str, ...],
    validate_token_resource: bool,
    http_oauth_issuer_url: str | None,
    http_oauth_client_id: str | None,
    http_oauth_client_secret: str | None,
    http_oauth_audience: str | None,
    google_client_id: str | None,
    google_client_secret: str | None,
    google_oauth_scopes: str | None,
    log_level: LogLevel,
) -> None:
    """Run the MCP server."""
    level: LogLevel = log_level.upper()  # type: ignore[assignment]

    allowed_hosts = _clean_tuple(allowed_hosts)
    allowed_origins = _clean_tuple(allowed_origins)
    oauth_jwt_algorithms = _clean_tuple(oauth_jwt_algorithms)
    oauth_required_scopes = _clean_tuple(oauth_required_scopes)

    effective_resource_url = (resource_server_url or "").strip() or f"http://{host}:{port}"

    redis_client: Redis | None = None
    event_store: RedisEventStore | None = None
    session_store: RedisSessionStore | None = None
    if redis_url and redis_url.strip():
        redis_client = Redis.from_url(redis_url.strip())
        event_store = RedisEventStore(redis_client)
        session_store = RedisSessionStore(redis_client)

    auth_settings: AuthSettings | None = None
    verifier: TokenVerifier | None = None

    effective_client_id = (oauth_client_id or "").strip() or (oauth_audience or "").strip() or None

    if oauth_issuer_url and oauth_issuer_url.strip():
        if (oauth_jwks_url and oauth_jwks_url.strip()) or (oauth_jwt_secret and oauth_jwt_secret.strip()):
            verifier = JWTTokenVerifier(
                issuer_url=oauth_issuer_url.strip(),
                resource_server_url=effective_resource_url,
                audience=oauth_audience.strip() if oauth_audience and oauth_audience.strip() else None,
                jwks_url=oauth_jwks_url.strip() if oauth_jwks_url and oauth_jwks_url.strip() else None,
                secret_or_key=oauth_jwt_secret.strip() if oauth_jwt_secret and oauth_jwt_secret.strip() else None,
                algorithms=list(oauth_jwt_algorithms) if oauth_jwt_algorithms else None,
                session_store=session_store,
            )
        elif oauth_introspection_url and oauth_introspection_url.strip():
            verifier = IntrospectionTokenVerifier(
                introspection_url=oauth_introspection_url.strip(),
                issuer_url=oauth_issuer_url.strip(),
                resource_server_url=effective_resource_url,
                client_id=effective_client_id,
                client_secret=oauth_client_secret.strip() if oauth_client_secret and oauth_client_secret.strip() else None,
                session_store=session_store,
            )
        else:
            raise click.UsageError(
                "When --oauth-issuer-url is provided, you must also specify one of: "
                "--oauth-jwks-url, --oauth-jwt-secret, or --oauth-introspection-url."
            )

        auth_settings = create_auth_settings(
            issuer_url=oauth_issuer_url.strip(),
            resource_server_url=effective_resource_url,
            required_scopes=list(oauth_required_scopes) if oauth_required_scopes else None,
            validate_token_resource=validate_token_resource,
        )

    effective_google_secret = (
        (google_client_secret or "").strip()
        or os.environ.get("GOOGLE_CLIENT_SECRET_ID", "").strip()
        or os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
        or None
    )

    mcp = create_server(
        auth=auth_settings,
        token_verifier=verifier,
        redis_client=redis_client,
        session_store=session_store,
        base_url=effective_resource_url,
        log_level=level,
        oauth_client_id=effective_client_id,
        oauth_client_secret=oauth_client_secret.strip() if oauth_client_secret else None,
        oauth_audience=oauth_audience.strip() if oauth_audience else None,
        http_oauth_issuer_url=http_oauth_issuer_url.strip() if http_oauth_issuer_url else None,
        http_oauth_client_id=http_oauth_client_id.strip() if http_oauth_client_id else None,
        http_oauth_client_secret=http_oauth_client_secret.strip() if http_oauth_client_secret else None,
        http_oauth_audience=http_oauth_audience.strip() if http_oauth_audience else None,
        google_client_id=google_client_id.strip() if google_client_id else None,
        google_client_secret=effective_google_secret,
        google_oauth_scopes=google_oauth_scopes.strip() if google_oauth_scopes else None,
    )

    if transport == "stdio":
        mcp.run(transport="stdio")
        return

    transport_security = build_transport_security(
        host=host,
        resource_server_url=resource_server_url.strip() if resource_server_url and resource_server_url.strip() else None,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
        disable_dns_rebinding_protection=disable_dns_rebinding_protection,
    )

    if transport == "sse":
        starlette_app = mcp.sse_app(
            host=host,
            transport_security=transport_security,
        )
    else:
        starlette_app = mcp.streamable_http_app(
            host=host,
            transport_security=transport_security,
            event_store=event_store,
        )

    app_with_logging = RequestLoggingMiddleware(starlette_app)
    cors_app = CORSMiddleware(
        app_with_logging,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    config = uvicorn.Config(
        cors_app,
        host=host,
        port=port,
        log_level=level.lower(),
        proxy_headers=proxy_headers,
        forwarded_allow_ips=forwarded_allow_ips,
    )
    server = uvicorn.Server(config)
    anyio.run(server.serve)


if __name__ == "__main__":
    main()
