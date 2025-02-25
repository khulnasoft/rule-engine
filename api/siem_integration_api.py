from flask import Blueprint, request, jsonify
from engine.integration.siem_integration import send_to_siem

siem_integration_bp = Blueprint('siem_integration', __name__)

@siem_integration_bp.route('/send', methods=['POST'])
def send_rule_to_siem():
    try:
        rule_path = request.json.get('rule_path')
        if not rule_path:
            return jsonify({"error": "rule_path is required"}), 400

        send_to_siem(rule_path)
        return jsonify({"status": "success", "message": "Rule sent to SIEM successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
