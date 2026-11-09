"""Authentication and OAuth 2.0 routes for Authentik (IdP 1) and Google (IdP 2)."""

from __future__ import annotations

import json
import logging
import os
import secrets
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, urlparse

import httpx
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from mcp_server.session import current_user_sub

if TYPE_CHECKING:
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.mcpserver import MCPServer
    from redis.asyncio import Redis

    from mcp_server.session import RedisSessionStore

logger = logging.getLogger(__name__)


def _resolve_oauth_endpoints(issuer_url: str) -> tuple[str, str]:
    """Derive authorization_endpoint and token_endpoint from issuer or OIDC structure.

    In Authentik, issuer is https://authentik.odoo.plus/application/o/<slug>/
    but authorization_endpoint is https://authentik.odoo.plus/application/o/authorize/
    and token_endpoint is https://authentik.odoo.plus/application/o/token/.
    """
    clean_issuer = issuer_url.rstrip("/")
    auth_ep = os.environ.get("MCP_HTTP_OAUTH_AUTHORIZE_URL", "").strip()
    token_ep = os.environ.get("MCP_HTTP_OAUTH_TOKEN_URL", "").strip()

    if auth_ep and token_ep:
        return auth_ep, token_ep

    if "/application/o/" in clean_issuer:
        prefix = clean_issuer.split("/application/o/")[0]
        authentik_base = f"{prefix}/application/o/"
        return (
            auth_ep or f"{authentik_base}authorize/",
            token_ep or f"{authentik_base}token/",
        )

    return (
        auth_ep or f"{clean_issuer}/authorize/",
        token_ep or f"{clean_issuer}/token/",
    )


def register_auth_routes(
    mcp: MCPServer,
    *,
    auth: AuthSettings | None = None,
    session_store: RedisSessionStore | None = None,
    redis_client: Redis | None = None,
    base_url: str | None = None,
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
) -> None:
    """Register OAuth login, callback, status, and logout endpoints."""
    raw_base = (base_url or "https://mcp.odoo.plus").rstrip("/")
    parsed = urlparse(raw_base)
    origin_base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else raw_base

    # HTTP browser session OAuth settings (uses MCP_HTTP_OAUTH_* with fallback)
    effective_http_issuer = (
        (http_oauth_issuer_url or "").strip()
        or os.environ.get("MCP_HTTP_OAUTH_ISSUER_URL", "").strip()
        or os.environ.get("MCP_HTTP_OAUTH_ISSUER", "").strip()
        or (str(auth.issuer_url).rstrip("/") if auth and auth.issuer_url else "")
        or os.environ.get("MCP_OAUTH_ISSUER_URL", "").strip()
    ).rstrip("/")

    authorize_endpoint, token_endpoint = _resolve_oauth_endpoints(effective_http_issuer)

    effective_http_client_id = (
        (http_oauth_client_id or "").strip()
        or os.environ.get("MCP_HTTP_OAUTH_CLIENT_ID", "").strip()
        or (oauth_client_id or "").strip()
        or os.environ.get("MCP_OAUTH_CLIENT_ID", "").strip()
        or (oauth_audience or "").strip()
        or os.environ.get("MCP_OAUTH_AUDIENCE", "").strip()
    )

    effective_http_client_secret = (
        (http_oauth_client_secret or "").strip()
        or os.environ.get("MCP_HTTP_OAUTH_CLIENT_SECRET", "").strip()
        or (oauth_client_secret or "").strip()
        or os.environ.get("MCP_OAUTH_CLIENT_SECRET", "").strip()
    )

    effective_http_audience = (
        (http_oauth_audience or "").strip()
        or os.environ.get("MCP_HTTP_OAUTH_AUDIENCE", "").strip()
        or (oauth_audience or "").strip()
        or os.environ.get("MCP_OAUTH_AUDIENCE", "").strip()
        or None
    )

    @mcp.custom_route("/auth/login", methods=["GET"])
    async def auth_login(request: Request) -> Response:
        """Initiate OAuth 2.0 authorization code flow with Authentik to bind the browser session."""
        if not effective_http_issuer or not authorize_endpoint:
            return Response("OAuth issuer URL is not configured.", status_code=500)

        client_id = effective_http_client_id
        if not client_id:
            return Response("MCP HTTP OAuth client ID is not configured.", status_code=500)

        next_url = request.query_params.get("next", "/auth/status")

        state = secrets.token_urlsafe(32)
        if redis_client:
            await redis_client.set(f"auth:state:{state}", json.dumps({"next": next_url}), ex=600)

        redirect_uri = f"{origin_base}/auth/callback"
        auth_url = (
            f"{authorize_endpoint}?"
            f"client_id={quote(client_id)}&"
            f"response_type=code&"
            f"redirect_uri={quote(redirect_uri)}&"
            f"scope={quote('openid email profile offline_access')}&"
            f"state={quote(state)}"
        )
        return RedirectResponse(url=auth_url, status_code=302)

    @mcp.custom_route("/auth/callback", methods=["GET"])
    async def auth_callback(request: Request) -> Response:
        """Handle OAuth 2.0 callback from Authentik, bind session/{sub}, set session cookie."""
        error = request.query_params.get("error")
        if error:
            desc = request.query_params.get("error_description", error)
            return HTMLResponse(f"<h3>Authentication error</h3><p>{desc}</p>", status_code=400)

        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return Response("Missing code or state parameter", status_code=400)

        next_url = "/auth/status"
        if redis_client:
            state_data_raw = await redis_client.get(f"auth:state:{state}")
            if not state_data_raw:
                return Response("Invalid or expired state parameter", status_code=400)
            await redis_client.delete(f"auth:state:{state}")
            try:
                state_data = json.loads(state_data_raw)
                next_url = state_data.get("next", "/auth/status")
            except Exception as exc:
                logger.warning("Error parsing state data: %s", exc, exc_info=exc)

        token_url = token_endpoint
        client_id = effective_http_client_id
        redirect_uri = f"{origin_base}/auth/callback"

        post_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }
        if effective_http_client_secret:
            post_data["client_secret"] = effective_http_client_secret

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                token_resp = await client.post(token_url, data=post_data, headers={"Accept": "application/json"})
            if token_resp.status_code != 200:
                logger.error("Failed to exchange code at Authentik (%s): %s", token_url, token_resp.text)
                return HTMLResponse(f"<h3>Token exchange failed</h3><pre>{token_resp.text}</pre>", status_code=502)
            tokens = token_resp.json()
        except Exception as exc:
            logger.error("Error exchanging code with Authentik: %s", exc, exc_info=exc)
            return Response("Internal server error", status_code=500)

        claims: dict[str, Any] = {}
        for key in ("id_token", "access_token"):
            jwt_raw = tokens.get(key)
            if jwt_raw:
                decoded_claim = None
                if effective_http_audience:
                    try:
                        decoded_claim = jwt.decode(
                            jwt_raw,
                            options={"verify_signature": False, "verify_exp": False},
                            audience=effective_http_audience,
                        )
                    except Exception as exc:
                        logger.debug(
                            "Decoding %s with audience %s failed: %s",
                            key,
                            effective_http_audience,
                            exc,
                            exc_info=exc,
                        )
                if not decoded_claim:
                    try:
                        decoded_claim = jwt.decode(
                            jwt_raw,
                            options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
                        )
                    except Exception as exc:
                        logger.debug(
                            "Decoding %s without audience validation failed: %s",
                            key,
                            exc,
                            exc_info=exc,
                        )
                if decoded_claim:
                    claims.update(decoded_claim)

        sub = str(claims.get("sub") or "")
        if not sub:
            return Response("Could not extract user 'sub' from Authentik tokens", status_code=500)

        if session_store:
            await session_store.create_or_update_session(sub=sub, claims=claims)

        current_user_sub.set(sub)
        resp = RedirectResponse(url=next_url, status_code=302)
        resp.set_cookie(
            key="mcp_sub",
            value=sub,
            max_age=86400 * 30,
            httponly=True,
            samesite="lax",
            secure=True,
            path="/",
        )
        return resp

    @mcp.custom_route("/auth/google/login", methods=["GET"])
    async def google_login(request: Request) -> Response:
        """Initiate OAuth 2.0 flow to link a Google account and bind its Bearer token to session/{sub}."""
        sub = request.query_params.get("sub") or request.cookies.get("mcp_sub") or current_user_sub.get()
        if not sub:
            return RedirectResponse(url="/auth/login?next=/auth/google/login", status_code=302)

        cid = (
            (google_client_id or "").strip()
            or os.environ.get("GOOGLE_CLIENT_ID", "").strip()
        )
        if not cid:
            return HTMLResponse(
                "<h3>Google Client ID not configured</h3>"
                "<p>Set <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET_ID</code> in <code>.env</code>.</p>",
                status_code=500,
            )

        state = secrets.token_urlsafe(32)
        if redis_client:
            await redis_client.set(f"auth:google_state:{state}", json.dumps({"sub": sub}), ex=600)

        redirect_uri = f"{origin_base}/auth/google/callback"
        default_scopes = (
            "openid email https://www.googleapis.com/auth/generative-language.retriever "
            "https://www.googleapis.com/auth/generative-language.tuning"
        )
        scopes = google_oauth_scopes or os.environ.get("GOOGLE_OAUTH_SCOPES", "").strip() or default_scopes

        google_auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={quote(cid)}&"
            f"redirect_uri={quote(redirect_uri)}&"
            "response_type=code&"
            f"scope={quote(scopes)}&"
            "access_type=offline&"
            "prompt=consent&"
            f"state={quote(state)}"
        )
        return RedirectResponse(url=google_auth_url, status_code=302)

    @mcp.custom_route("/auth/google/callback", methods=["GET"])
    async def google_callback(request: Request) -> Response:
        """Handle Google OAuth 2.0 code callback, exchange for token, store in session/{sub}."""
        error = request.query_params.get("error")
        if error:
            return HTMLResponse(f"<h3>Google OAuth Error: {error}</h3>", status_code=400)

        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return Response("Missing code or state parameter", status_code=400)

        sub: str | None = None
        if redis_client:
            state_raw = await redis_client.get(f"auth:google_state:{state}")
            if not state_raw:
                return Response("Invalid or expired state parameter", status_code=400)
            await redis_client.delete(f"auth:google_state:{state}")
            try:
                state_data = json.loads(state_raw)
                sub = state_data.get("sub")
            except Exception as exc:
                logger.warning("Error parsing Google OAuth state: %s", exc, exc_info=exc)

        if not sub:
            sub = request.cookies.get("mcp_sub") or current_user_sub.get()

        if not sub:
            return Response("Could not associate Google token: user sub session missing.", status_code=400)

        cid = (
            (google_client_id or "").strip()
            or os.environ.get("GOOGLE_CLIENT_ID", "").strip()
        )
        csec = (
            (google_client_secret or "").strip()
            or os.environ.get("GOOGLE_CLIENT_SECRET_ID", "").strip()
            or os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
        )
        redirect_uri = f"{origin_base}/auth/google/callback"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    "https://oauth2.googleapis.com/token",
                    data={
                        "client_id": cid,
                        "client_secret": csec,
                        "code": code,
                        "grant_type": "authorization_code",
                        "redirect_uri": redirect_uri,
                    },
                    headers={"Accept": "application/json"},
                )
            if resp.status_code != 200:
                logger.error("Failed to exchange code at Google: %s", resp.text)
                return HTMLResponse(f"<h3>Google token exchange failed</h3><pre>{resp.text}</pre>", status_code=502)
            google_tokens = resp.json()
        except Exception as exc:
            logger.error("Exception exchanging code with Google: %s", exc, exc_info=exc)
            return Response("Internal server error", status_code=500)

        if session_store:
            await session_store.store_google_tokens(sub=sub, tokens=google_tokens)

        return HTMLResponse(
            f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Google Connected</title>'
            f'<style>body{{font-family:system-ui,-apple-system,sans-serif;max-width:600px;margin:50px auto;padding:24px;line-height:1.5;}}'
            f'.card{{border:1px solid #dadce0;border-radius:12px;padding:24px;background:#f8f9fa;box-shadow:0 1px 4px rgba(0,0,0,0.08);}}'
            f'a{{color:#1a73e8;text-decoration:none;font-weight:500;}}</style></head><body>'
            f'<div class="card">'
            f'<h2>✅ Google Account Connected!</h2>'
            f'<p>Your Google Bearer token has been successfully stored in Redis under <code>session/{sub}</code>.</p>'
            f'<p>MCP tools can now access this Bearer token to communicate with Gemini APIs on your behalf.</p>'
            f'<p><a href="/auth/status">View Session Status &rarr;</a></p>'
            f'</div></body></html>'
        )

    @mcp.custom_route("/auth/status", methods=["GET"])
    async def auth_status(request: Request) -> Response:
        """Display current authentication and session status."""
        sub = request.cookies.get("mcp_sub") or current_user_sub.get()
        session_data = None
        if sub and session_store:
            session_data = await session_store.get_session(sub)

        gt = (session_data or {}).get("google_tokens") or {}
        has_google = bool(gt.get("access_token"))
        google_expires = gt.get("expires_at")

        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({
                "authenticated": bool(sub),
                "sub": sub,
                "session_key": f"session/{sub}" if sub else None,
                "google_linked": has_google,
                "google_expires_at": google_expires,
                "session": session_data,
            })

        sub_display = f"<code>{sub}</code>" if sub else "<em>Not logged in</em>"
        google_display = (
            f"<strong style='color:#137333;'>Connected</strong> (expires timestamp: {google_expires})"
            if has_google
            else "<span style='color:#5f6368;'>Not linked</span> &nbsp; <a href='/auth/google/login' style='padding:4px 10px;background:#1a73e8;color:#fff;border-radius:4px;text-decoration:none;font-size:13px;'>Link Google Account</a>"
        )
        login_btn = (
            "<a href='/auth/logout' style='color:#d93025;text-decoration:none;font-weight:500;'>Log out</a>"
            if sub
            else "<a href='/auth/login' style='padding:8px 16px;background:#1a73e8;color:#fff;border-radius:6px;text-decoration:none;font-weight:500;'>Log in with Authentik</a>"
        )

        return HTMLResponse(
            f'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>MCP Session Status</title>'
            f'<style>body{{font-family:system-ui,-apple-system,sans-serif;max-width:650px;margin:40px auto;padding:20px;line-height:1.6;}}'
            f'.card{{border:1px solid #dadce0;border-radius:12px;padding:24px;box-shadow:0 1px 4px rgba(0,0,0,0.08);}}'
            f'table{{width:100%;border-collapse:collapse;margin:16px 0;}}'
            f'td{{padding:10px 8px;border-bottom:1px solid #eee;}}'
            f'td:first-child{{font-weight:600;width:35%;color:#555;}}'
            f'</style></head><body>'
            f'<div class="card">'
            f'<h2>🔐 MCP Session & OAuth Status</h2>'
            f'<table>'
            f'<tr><td>User Identity (sub)</td><td>{sub_display}</td></tr>'
            f'<tr><td>Redis Session Key</td><td><code>{"session/" + sub if sub else "None"}</code></td></tr>'
            f'<tr><td>Google Token Binding</td><td>{google_display}</td></tr>'
            f'</table>'
            f'<div style="margin-top:20px;">{login_btn}</div>'
            f'</div></body></html>'
        )

    @mcp.custom_route("/auth/logout", methods=["GET"])
    async def auth_logout(_request: Request) -> Response:
        """Clear the session cookie."""
        resp = RedirectResponse(url="/auth/status", status_code=302)
        resp.delete_cookie(key="mcp_sub", path="/")
        return resp
