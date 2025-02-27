from flask import Blueprint, request, jsonify, current_app as app
from engine.integration.siem_integration import send_to_siem
import os

siem_integration_bp = Blueprint('siem_integration', __name__)

@siem_integration_bp.route('/send', methods=['POST'])
def send_rule_to_siem():
    try:
        rule_path = request.json.get('rule_path')
        if not rule_path:
            return jsonify({"error": "rule_path is required"}), 400

        # Validate the existence of the rule file
        if not os.path.exists(rule_path):
            raise FileNotFoundError(f"Rule file at {rule_path} not found.")

        send_to_siem(rule_path)
        return jsonify({"status": "success", "message": "Rule sent to SIEM successfully"})
    except ValueError as ve:
        app.logger.error("ValueError occurred: %s", str(ve))
        return jsonify({"error": str(ve)}), 400
    except FileNotFoundError as fnfe:
        app.logger.error("FileNotFoundError occurred: %s", str(fnfe))
        return jsonify({"error": str(fnfe)}), 404
    except Exception as e:
        app.logger.error("An error occurred: %s", str(e))
        return jsonify({"error": "An internal error has occurred!"}), 500
