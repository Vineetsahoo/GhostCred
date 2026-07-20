# Stage 1: Build environment
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
COPY pyproject.toml .
COPY ghostcred/ ghostcred/
COPY tests/ tests/
COPY *.py .

# Install dependencies into a separate directory for easy copying
RUN pip install --no-cache-dir --target=/build/site-packages .

# Stage 2: Distroless runtime
FROM gcr.io/distroless/python3-debian12

WORKDIR /app

# Copy site-packages from the builder stage
COPY --from=builder /build/site-packages /usr/lib/python3.11/site-packages
ENV PYTHONPATH=/usr/lib/python3.11/site-packages

# Copy only the CLI entrypoint script wrapper (or just run module directly)
# Since the CLI is installed in site-packages, we can run it using python -m ghostcred.cli
ENTRYPOINT ["python", "-m", "ghostcred.cli"]
