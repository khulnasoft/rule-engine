import os

def validate_path(path):
    """Check if a given file path exists."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File at {path} not found.")
    return path

def handle_missing_field_error(field_name):
    """Helper function to handle missing required fields in request data."""
    return {"error": f"{field_name} is required"}, 400

def handle_unsupported_format_error(format_name):
    """Helper function to handle unsupported format errors."""
    return {"error": f"Unsupported {format_name} format"}, 400

def handle_internal_server_error():
    """Helper function to handle internal server errors."""
    return {"error": "An internal error has occurred!"}, 500

def log_error(logger, error_message):
    """Helper function to log errors with sufficient detail."""
    logger.error("An error occurred: %s", error_message)
