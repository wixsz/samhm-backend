# =====================================================
# Stable Alpine Base
# =====================================================
FROM python:3.11-alpine

# =====================================================
# Environment
# =====================================================
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# =====================================================
# Install system dependencies
# =====================================================
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    curl

# =====================================================
# Workdir
# =====================================================
WORKDIR /app

# =====================================================
# Install Python dependencies first (cache layer)
# =====================================================
COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# =====================================================
# Copy project files
# =====================================================
COPY . .

# =====================================================
# Create logs directory
# =====================================================
RUN mkdir -p /app/logs

# =====================================================
# Expose port
# =====================================================
EXPOSE 8000

# =====================================================
# Healthcheck (stable)
# =====================================================
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
 CMD curl -f http://localhost:8000/api/v1/health || exit 1

# =====================================================
# Start server (FIXED — no restart loop)
# =====================================================
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
