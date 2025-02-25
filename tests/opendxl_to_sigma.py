# rule-engine/engine/converters/opendxl_to_sigma.py

def convert_opendxl_to_sigma(opendxl_rule):
    """Convert OpenDXL rule to Sigma format."""
    sigma_rule = {
        'title': opendxl_rule.get('title', 'Unknown'),
        'description': opendxl_rule.get('description', 'No description'),
        'logsource': {
            'category': 'process_creation',
            'product': 'windows'
        },
        'detection': {
            'selection': {
                'CommandLine': opendxl_rule.get('command_line', [])
            },
            'condition': opendxl_rule.get('condition', 'all of them')
        },
        'level': 'high',
        'id': 'generated-id',
        'behaviorgroup': '5',
        'classification': '8'
    }
    return sigma_rule
