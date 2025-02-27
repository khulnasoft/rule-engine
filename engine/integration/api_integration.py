# rule-engine/engine/integration/api_integration.py
from flask import Flask, request, jsonify
from engine.parsers.load_rules import load_rule

app = Flask(__name__)

@app.route('/validate_rule', methods=['POST'])
def validate_rule():
    """Endpoint to validate a rule."""
    try:
        file_path = request.json['file_path']
        rule = load_rule(file_path)
        return jsonify({"status": "success", "rule": rule}), 200
    except FileNotFoundError as fnfe:
        app.logger.error("FileNotFoundError occurred: %s", str(fnfe))
        return jsonify({"status": "error", "message": "File not found"}), 404
    except ValueError as ve:
        app.logger.error("ValueError occurred: %s", str(ve))
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        app.logger.error("An error occurred: %s", str(e))
        return jsonify({"status": "error", "message": "An internal error has occurred!"}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
