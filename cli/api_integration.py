from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/validate_rule', methods=['POST'])
def validate_rule():
    rule_data = request.json
    # Validate the rule here
    return jsonify({"status": "success", "message": "Rule validated successfully"})

if __name__ == "__main__":
    app.run(debug=True)
