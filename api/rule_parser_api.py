from flask import Blueprint, request, jsonify, current_app as app
from engine.parsers.sigma_parser import load_sigma_rule
from engine.parsers.wazuh_parser import load_wazuh_rule

rule_parser_bp = Blueprint('rule_parser', __name__)

@rule_parser_bp.route('/validate', methods=['POST'])
def validate_rule():
    try:
        rule_data = request.json
        rule_format = rule_data.get('format')
        rule_content = rule_data.get('rule')

        if not rule_format or not rule_content:
            return jsonify({"error": "Both 'format' and 'rule' fields are required"}), 400

        if rule_format == 'sigma':
            load_sigma_rule(rule_content)
        elif rule_format == 'wazuh':
            load_wazuh_rule(rule_content)
        else:
            app.logger.error("Unsupported rule format: %s", rule_format)
            return jsonify({"error": "Unsupported rule format"}), 400

        return jsonify({"status": "success", "message": "Rule validated successfully"})
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": "An internal error has occurred!"}), 500
