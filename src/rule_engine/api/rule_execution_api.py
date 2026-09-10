from flask import Blueprint, request, jsonify, current_app as app
from rule_engine.engine.executors import execute_rules
import os

rule_execution_bp = Blueprint('rule_execution', __name__)

@rule_execution_bp.route('/execute', methods=['POST'])
def execute_rule_on_logs():
    try:
        log_file = request.json.get('log_file')
        rules = request.json.get('rules', [])
        if not log_file:
            return jsonify({"error": "log_file is required"}), 400
        if not os.path.exists(log_file):
            raise FileNotFoundError(f"Log file at {log_file} not found.")
        results = execute_rules(rules, log_file)
        return jsonify({"status": "success", "results": results})
    except FileNotFoundError as fnfe:
        app.logger.error("FileNotFoundError occurred: %s", str(fnfe))
        return jsonify({"error": str(fnfe)}), 404
    except Exception as e:
        app.logger.error("An error occurred: %s", str(e))
        return jsonify({"error": "An internal error has occurred!"}), 500
