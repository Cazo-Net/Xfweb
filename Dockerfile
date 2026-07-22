# ============================================
# Xfweb - Multi-stage Docker Build
# The Beast: Next-gen Web Security Scanner
# ============================================

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .

# Stage 2: Runtime
FROM python:3.11-slim AS runtime

LABEL maintainer="Xfweb Contributors"
LABEL description="Xfweb - The Beast: Next-gen web application security scanner"
LABEL version="1.0.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libffi8 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r xfweb && useradd -r -g xfweb -d /app xfweb

# Copy installed packages
COPY --from=builder /install /usr/local

# Install Playwright browsers
RUN playwright install chromium

# Set up app directory
WORKDIR /app
RUN chown -R xfweb:xfweb /app

USER xfweb

# Default ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["xfweb"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
