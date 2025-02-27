from flask import Blueprint, request, jsonify, current_app as app
from engine.execution import execute_rules

rule_execution_bp = Blueprint('rule_execution', __name__)

@rule_execution_bp.route('/execute', methods=['POST'])
def execute_rule_on_logs():
    try:
        log_file = request.json.get('log_file')
        if not log_file:
            return jsonify({"error": "log_file is required"}), 400

        execute_rules(log_file)
        return jsonify({"status": "success", "message": "Rules executed successfully"})
    except ValueError as ve:
        app.logger.error("ValueError occurred: %s", str(ve))
        return jsonify({"error": str(ve)}), 400
    except FileNotFoundError as fnfe:
        app.logger.error("FileNotFoundError occurred: %s", str(fnfe))
        return jsonify({"error": str(fnfe)}), 404
    except Exception as e:
        app.logger.error("An error occurred: %s", str(e))
        return jsonify({"error": "An internal error has occurred!"}), 500
