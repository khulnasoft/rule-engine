import os

def validate_path(path):
    """Check if a given file path exists."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File at {path} not found.")
    return path
