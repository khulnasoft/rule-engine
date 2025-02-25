# Makefile for Rule Engine CLI Project

# Define variables
PYTHON = python3
PIP = pip
VENV_DIR = venv
DOCKER_IMAGE = rule-engine
DOCKER_CONTAINER = rule-engine-container
FLASK_APP = rule-engine/api/app.py
FLASK_PORT = 5000

# Create a virtual environment and install dependencies
venv: 
	@echo "Creating virtual environment..."
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "Activating virtual environment..."
	. $(VENV_DIR)/bin/activate && $(PIP) install -r requirements.txt

# Install dependencies
install:
	@echo "Installing dependencies..."
	$(PIP) install -r requirements.txt

# Run the Flask development server
run:
	@echo "Running Flask API server..."
	FLASK_APP=$(FLASK_APP) flask run --host=0.0.0.0 --port=$(FLASK_PORT)

# Run tests
test:
	@echo "Running tests..."
	. $(VENV_DIR)/bin/activate && pytest

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
