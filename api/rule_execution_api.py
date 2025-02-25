from flask import Blueprint, request, jsonify
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500
