# =====================================================
# Stable Debian Base (NO ALPINE)
# =====================================================
FROM python:3.11-slim

# =====================================================
# Environment
# =====================================================
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# =====================================================
# Install minimal system dependencies
# =====================================================
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

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
# Copy backend code (INCLUDING AI MODEL)
# =====================================================
COPY app ./app

# =====================================================
# Create logs directory
# =====================================================
RUN mkdir -p /app/logs

# =====================================================
# Expose port
# =====================================================
EXPOSE 8000

# =====================================================
# Healthcheck
# =====================================================
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# =====================================================
# Start server
# =====================================================
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]