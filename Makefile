# Makefile for Rule Engine CLI Project

# Define variables
UV = uv
VENV_DIR = .venv
DOCKER_IMAGE = rule-engine
DOCKER_CONTAINER = rule-engine-container
FLASK_APP = rule-engine/api/app.py
FLASK_PORT = 5000

# Create a virtual environment and install dependencies using UV
venv:
	@echo "Creating virtual environment..."
	$(UV) venv
	@echo "Installing dependencies..."
	$(UV) sync

# Install dependencies
install:
	@echo "Installing dependencies..."
	$(UV) sync

# Run the Flask development server
run:
	@echo "Running Flask API server..."
	$(UV) run flask run --host=0.0.0.0 --port=$(FLASK_PORT)

# Run tests
test:
	@echo "Running tests..."
	$(UV) run pytest

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

# Docker run
docker-run:
	@echo "Running Docker container..."
	docker run -d -p $(FLASK_PORT):$(FLASK_PORT) --name $(DOCKER_CONTAINER) $(DOCKER_IMAGE)

# Docker stop
docker-stop:
	@echo "Stopping Docker container..."
	docker stop $(DOCKER_CONTAINER)
	docker rm $(DOCKER_CONTAINER)

# Clean up virtual environment
clean:
	@echo "Cleaning up virtual environment..."
	rm -rf $(VENV_DIR)

# Docker build, run, and test the container
docker-dev: docker-build docker-run test
