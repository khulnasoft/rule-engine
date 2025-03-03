import os
import sys
from flask import Flask
from rule_parser_api import rule_parser_bp
from rule_execution_api import rule_execution_bp
from rule_conversion_api import rule_conversion_bp
from siem_integration_api import siem_integration_bp

# Add the root directory to the Python path
root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(root_path)

# Print the Python path for debugging
print("Python path:", sys.path)

app = Flask(__name__)

# Register Blueprints
app.register_blueprint(rule_parser_bp, url_prefix='/api/rule_parser')
app.register_blueprint(rule_execution_bp, url_prefix='/api/rule_execution')
app.register_blueprint(rule_conversion_bp, url_prefix='/api/rule_conversion')
app.register_blueprint(siem_integration_bp, url_prefix='/api/siem_integration')

@app.route('/')
def home():
    return "Rule Engine API"

if __name__ == "__main__":
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)
