from flask import Blueprint, request, jsonify
from engine.converters.sigma_to_yara import convert_sigma_to_yara
from engine.converters.sigma_to_wazuh import convert_sigma_to_wazuh

rule_conversion_bp = Blueprint('rule_conversion', __name__)

@rule_conversion_bp.route('/convert', methods=['POST'])
def convert_rule():
    try:
        rule_data = request.json
        rule_format = rule_data.get('format')
        rule_content = rule_data.get('rule')

        if not rule_format or not rule_content:
            return jsonify({"error": "Both 'format' and 'rule' fields are required"}), 400

        if rule_format == 'yara':
            converted_rule = convert_sigma_to_yara(rule_content)
        elif rule_format == 'wazuh':
            converted_rule = convert_sigma_to_wazuh(rule_content)
        else:
            return jsonify({"error": "Unsupported conversion format"}), 400

        return jsonify({"status": "success", "converted_rule": converted_rule})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "An internal error has occurred!"}), 500
