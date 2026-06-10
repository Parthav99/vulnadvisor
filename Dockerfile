# File: Dockerfile
# Container image for the VulnAdvisor platform backend (FastAPI).
#
# The backend lives in platform/ but imports the core `vulnadvisor` package at runtime
# (e.g. vulnadvisor.model.reachability), so the image installs BOTH the project and the
# `platform` dependency group — but never the `dev` group. Build context is the repo root
# because uv needs pyproject.toml, uv.lock, and src/ to install the project.
#
# Build: docker build -t vulnadvisor-platform .
# Run:   docker run -p 8080:8080 -e DATABASE_URL=... -e SECRET_KEY=... vulnadvisor-platform

# ---- builder: resolve and install dependencies into a venv ----
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

# Byte-compile for faster cold starts; copy (not hardlink) so the venv is relocatable.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Install dependencies first (cached layer keyed on the lockfile, not on source churn).
# --no-install-project here so a code edit doesn't bust the dependency cache.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --group platform --no-install-project

# Now add the project source and install the `vulnadvisor` package itself.
# --no-editable: install a real copy into site-packages (not a .pth pointing at /app/src),
# so the package survives into the runtime stage, which never copies src/.
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --group platform --no-editable

# ---- runtime: slim image with just Python + the prepared venv + app source ----
FROM python:3.12-slim-bookworm AS runtime

# Run as a non-root user (defense in depth; the container holds no source by design).
RUN useradd --create-home --uid 10001 appuser

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # platform/ is on the path so `vulnadvisor_platform` (source, not a wheel) imports cleanly.
    PYTHONPATH=/app/platform \
    PORT=8080

WORKDIR /app

# The venv (with vulnadvisor + platform deps) from the builder.
COPY --from=builder /app/.venv /app/.venv
# The backend source + Alembic config/migrations (alembic.ini lives in platform/).
COPY platform ./platform

USER appuser
EXPOSE 8080

# Apply pending migrations, then serve. Single worker fits the 256MB free tier; uvicorn is
# async so one worker handles concurrent requests. `sh -c` lets $PORT be overridden by Fly.
WORKDIR /app/platform
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn vulnadvisor_platform.app:app --host 0.0.0.0 --port ${PORT}"]
