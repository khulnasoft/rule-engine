# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set environment variables
ENV FLASK_APP=rule-engine/api/app.py
ENV FLASK_ENV=development
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5000

# Set working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY . /app/

# Expose the port Flask will run on
EXPOSE 5000

# Command to run the Flask application
CMD ["flask", "run"]
