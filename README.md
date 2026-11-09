# MCP Server

Minimal Model Context Protocol (MCP) Python project managed with [`uv`](https://docs.astral.sh/uv/), [`click`](https://click.palletsprojects.com/), and the official `mcp` Python SDK (`MCPServer`), featuring OAuth 2.0 Resource Server authentication and Traefik reverse-proxy integration.

## Project Structure

- `Dockerfile` & `docker-compose.yml` — Standalone Docker service connected to external `proxy-1` (`stack_proxy-1`) network with Traefik HTTP-to-HTTPS redirect (`redirect-https@file`) and TLS (`tls-resolver`).
- `.env.example` / `.env` — Environment variable configuration for Docker Compose and local runs.
- `pyproject.toml` — Project metadata, dependencies (`mcp[cli]`, `click`, `pyjwt[crypto]`, `httpx`), and CLI entrypoint (`mcp-server`).
- `src/mcp_server/auth.py` — OAuth 2.0 `TokenVerifier` implementations (`JWTTokenVerifier` and `IntrospectionTokenVerifier`) plus reverse-proxy transport security helpers.
- `src/mcp_server/tools/` — Modular MCP tools (`help`, `add`, `echo`, `whoami`).
- `src/mcp_server/server.py` — `create_server()` factory, `/health` endpoint, resources, prompts, and Click CLI entrypoint.

## Running with Docker Compose

1. Configure your environment variables in `.env` (see `.env.example`):
   ```bash
   cp .env.example .env
   ```
2. Build and start the service:
   ```bash
   docker compose up -d --build
   ```

The service attaches to the external `stack_proxy-1` network (`proxy-1`) and configures Traefik with:
- `traefik.enable=true`
- HTTP -> HTTPS redirect using `redirect-https@file`
- TLS termination using `tls-resolver`

## Running Locally with `uv`

```bash
# View CLI options
uv run mcp-server --help

# Run with streamable-http transport
uv run mcp-server --transport streamable-http --host 127.0.0.1 --port 8000
```
