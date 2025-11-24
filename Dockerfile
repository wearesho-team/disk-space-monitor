FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Create non-root user for security
RUN groupadd --gid 1000 monitor && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home monitor

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=monitor:monitor src/ ./src/

# Create health check file directory
RUN mkdir -p /app/health && chown monitor:monitor /app/health

# Switch to non-root user
USER monitor

# Health check - creates a file if the process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -f "python -m src.monitor" || exit 1

# Default environment variables
ENV HOSTFS_PREFIX=/hostfs \
    CHECK_INTERVAL=300 \
    WARNING_THRESHOLD=80 \
    CRITICAL_THRESHOLD=90 \
    ALERT_COOLDOWN=3600 \
    LOG_LEVEL=INFO

# Run the monitor
CMD ["python", "-m", "src.monitor"]
