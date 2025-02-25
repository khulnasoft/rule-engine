from flask import Blueprint, request, jsonify
from engine.parsers.sigma_parser import load_sigma_rule
from engine.parsers.wazuh_parser import load_wazuh_rule

rule_parser_bp = Blueprint('rule_parser', __name__)

@rule_parser_bp.route('/validate', methods=['POST'])
def validate_rule():
    try:
        rule_data = request.json
        rule_format = rule_data.get('format')
        rule_content = rule_data.get('rule')

        if rule_format == 'sigma':
            load_sigma_rule(rule_content)
        elif rule_format == 'wazuh':
            load_wazuh_rule(rule_content)
        else:
            return jsonify({"error": "Unsupported rule format"}), 400

        return jsonify({"status": "success", "message": "Rule validated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
