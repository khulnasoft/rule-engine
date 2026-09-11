import sys
import click
import logging
from rule_engine.cli.rule_parser import load_rule_cli, list_categories_cli
from rule_engine.cli.rule_execution import execute_rules_cli
from rule_engine.cli.rule_conversion import convert_rule_cli
from rule_engine.cli.siem_integration import send_to_siem_cli

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@click.group()
def cli():
    """CLI for managing rule engine."""
    pass

@cli.command()
@click.argument('rule_path')
def load(rule_path):
    """Load and validate a rule from a file."""
    try:
        load_rule_cli(rule_path)
        logger.info("Rule loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load rule: {e}")
        sys.exit(1)

@cli.command()
@click.argument('log_file')
@click.option('--rule', default=None, help='Path to a specific rule file')
def execute(log_file, rule):
    """Execute rules on log file."""
    try:
        execute_rules_cli(log_file, rule_path=rule)
        logger.info("Rules executed successfully.")
    except Exception as e:
        logger.error(f"Failed to execute rules: {e}")
        sys.exit(1)

@cli.command()
@click.argument('rule_path')
@click.argument('format')
def convert(rule_path, format):
    """Convert rule from one format to another."""
    try:
        convert_rule_cli(rule_path, format)
        logger.info("Rule converted successfully.")
    except Exception as e:
        logger.error(f"Failed to convert rule: {e}")
        sys.exit(1)

@cli.command()
@click.argument('rule_path')
@click.option('--siem-type', default='splunk', help='SIEM type')
def send(rule_path, siem_type):
    """Send rule to SIEM."""
    try:
        send_to_siem_cli(rule_path, siem_type)
        logger.info("Rule sent to SIEM successfully.")
    except Exception as e:
        logger.error(f"Failed to send rule to SIEM: {e}")
        sys.exit(1)

@cli.command()
def categories():
    """List all available categories."""
    try:
        list_categories_cli()
    except Exception as e:
        logger.error(f"Failed to list categories: {e}")
        sys.exit(1)

if __name__ == "__main__":
    cli()
