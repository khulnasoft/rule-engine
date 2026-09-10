# rule-engine/engine/converters/common.py

def validate_conversion_data(data, expected_fields):
    """Validate the required fields are present in the converted data."""
    missing_fields = [field for field in expected_fields if field not in data]
    if missing_fields:
        raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
    return True

def log_conversion(data):
    """Helper function to log the converted rule data."""
    print(f"Conversion Result: {data}")
