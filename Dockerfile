# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Non-root runtime user
RUN useradd -m -u 10001 mcp

WORKDIR /app

# Install build tooling, then the package itself from source
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && rm -rf /root/.cache

ENV MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8770 \
    HOME=/tmp \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER mcp

EXPOSE 8770

# Health endpoint served by the Starlette app
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8770/health',timeout=4).status==200 else 1)" || exit 1

ENTRYPOINT ["vmware-aria-logs"]
