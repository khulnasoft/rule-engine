from flask import Blueprint, request, jsonify
from engine.converters.sigma_to_yara import convert_sigma_to_yara
from engine.converters.sigma_to_wazuh import convert_sigma_to_wazuh

rule_conversion_bp = Blueprint('rule_conversion', __name__)

@rule_conversion_bp.route('/convert', methods=['POST'])
def convert_rule():
    """
    Convert a Sigma rule to the specified format (YARA or Wazuh).

    Parameters:
    - None (expects JSON payload in the request body with 'format' and 'rule' keys)

    Returns:
    - JSON response with the converted rule or an error message
    """
    try:
        rule_data = request.json
        rule_format = rule_data.get('format')
        rule_content = rule_data.get('rule')

        if not rule_format:
            return jsonify({"error": "format is required"}), 400
        if not rule_content:
            return jsonify({"error": "rule is required"}), 400

        # Check the requested conversion format and call the appropriate conversion function
        if rule_format == 'yara':
            converted_rule = convert_sigma_to_yara(rule_content)
        elif rule_format == 'wazuh':
            converted_rule = convert_sigma_to_wazuh(rule_content)
        else:
            return jsonify({"error": "Unsupported conversion format"}), 400

        return jsonify({"status": "success", "converted_rule": converted_rule})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except KeyError as e:
        return jsonify({"error": f"Missing key: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An internal error has occurred!"}), 500
