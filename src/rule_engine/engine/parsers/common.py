# rule-engine/engine/parsers/common.py

def validate_required_fields(rule, required_fields):
    """Validate that all required fields are present in the rule."""
    missing_fields = [field for field in required_fields if field not in rule]
    if missing_fields:
        print(f"Error: Missing required fields: {', '.join(missing_fields)}")
        return False
    return True

def extract_field_from_xml(element, field):
    """Helper function to extract a field from XML elements (for Wazuh parser)."""
    result = element.find(field)
    return result.text if result is not None else None

def log_error(message):
    """Helper function for logging errors."""
    print(f"ERROR: {message}")
