from flask import Blueprint, request, jsonify
from rule_engine.engine.converters.sigma_to_yara import convert_sigma_to_yara
from rule_engine.engine.converters.sigma_to_wazuh import convert_sigma_to_wazuh
from rule_engine.engine.converters.yara_to_sigma import convert_yara_to_sigma
from rule_engine.engine.converters.yara_to_wazuh import convert_yara_to_wazuh
from rule_engine.engine.converters.wazuh_to_sigma import convert_wazuh_to_sigma
from rule_engine.engine.converters.wazuh_to_yara import convert_wazuh_to_yara
from rule_engine.engine.models import RuleFormat

rule_conversion_bp = Blueprint('rule_conversion', __name__)

@rule_conversion_bp.route('/convert', methods=['POST'])
def convert_rule():
    try:
        rule_data = request.json
        rule_format = rule_data.get('format')
        rule_content = rule_data.get('rule')
        from_format = rule_data.get('from_format', 'sigma')

        if not rule_format:
            return jsonify({"error": "format is required"}), 400
        if not rule_content:
            return jsonify({"error": "rule is required"}), 400

        result = None
        if from_format == 'sigma' and rule_format == 'yara':
            result = convert_sigma_to_yara(rule_content)
        elif from_format == 'sigma' and rule_format == 'wazuh':
            result = convert_sigma_to_wazuh(rule_content)
        elif from_format == 'yara' and rule_format == 'sigma':
            result = convert_yara_to_sigma(rule_content)
        elif from_format == 'yara' and rule_format == 'wazuh':
            result = convert_yara_to_wazuh(rule_content)
        elif from_format == 'wazuh' and rule_format == 'sigma':
            result = convert_wazuh_to_sigma(rule_content)
        elif from_format == 'wazuh' and rule_format == 'yara':
            result = convert_wazuh_to_yara(rule_content)
        else:
            return jsonify({"error": "Unsupported conversion format"}), 400

        return jsonify({"status": "success", "converted_rule": result})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except KeyError as e:
        return jsonify({"error": f"Missing key: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": "An internal error has occurred!"}), 500
