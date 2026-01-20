# Use Python 3.11 slim image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash app

# Set work directory
WORKDIR /home/app

# Copy project files
COPY pyproject.toml .
COPY easylic/ ./easylic/
COPY README.md .

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Generate server keys (will be done at runtime if not present)
RUN easylic keygen

# Change ownership to app user
RUN chown -R app:app /home/app

# Switch to app user
USER app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Expose port
EXPOSE 8000

# Default command to run the server
CMD ["uvicorn", "easylic.server.core:app", "--host", "0.0.0.0", "--port", "8000"]