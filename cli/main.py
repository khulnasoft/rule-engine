import sys
import click
import logging
from rule_parser import load_rules
from rule_execution import execute_rules
from rule_conversion import convert_rule_format
from siem_integration import send_to_siem

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@click.group()
def cli():
    """CLI for managing rule engine."""
    pass

@cli.command()
@click.argument('rule_path')
def load(rule_path):
    """Load and validate rules from a file."""
    try:
        load_rules(rule_path)
        logger.info("Rules loaded and validated successfully.")
    except Exception as e:
        logger.error(f"Failed to load rules: {e}")
        sys.exit(1)

@cli.command()
@click.argument('log_file')
def execute(log_file):
    """Execute rules on logs."""
    try:
        execute_rules(log_file)
        logger.info("Rules executed on logs successfully.")
    except Exception as e:
        logger.error(f"Failed to execute rules: {e}")
        sys.exit(1)

@cli.command()
@click.argument('rule_path')
@click.argument('format')
def convert(rule_path, format):
    """Convert rule from one format to another."""
    try:
        convert_rule_format(rule_path, format)
        logger.info("Rule converted successfully.")
    except Exception as e:
        logger.error(f"Failed to convert rule: {e}")
        sys.exit(1)

@cli.command()
@click.argument('rule_path')
def send(rule_path):
    """Send rules to SIEM."""
    try:
        send_to_siem(rule_path)
        logger.info("Rule sent to SIEM successfully.")
    except Exception as e:
        logger.error(f"Failed to send rule to SIEM: {e}")
        sys.exit(1)

if __name__ == "__main__":
    cli()
