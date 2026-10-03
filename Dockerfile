# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package and its dependencies
RUN pip install --no-cache-dir hatchling
RUN pip install --no-cache-dir .

# Expose the port FastAPI runs on
EXPOSE 8000

# Run the FastAPI application using uvicorn
CMD ["uvicorn", "mcp_audit.gateway.app:app", "--host", "0.0.0.0", "--port", "8000"]
