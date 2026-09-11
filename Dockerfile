# Use an official Python runtime as the base image
FROM python:3.14-slim

# Install UV and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv

# Set environment variables
ENV FLASK_APP=src/rule_engine/api/app.py
ENV FLASK_ENV=development
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

# Set working directory inside the container
WORKDIR /app

# Copy project files
COPY . /app/

# Install dependencies using UV
RUN uv sync --frozen --no-dev

# Expose the port Flask will run on
EXPOSE 5000

# Command to run the Flask application
CMD ["uv", "run", "flask", "run"]
