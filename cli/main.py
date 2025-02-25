import sys
import click
from rule_parser import load_rules
from rule_execution import execute_rules
from rule_conversion import convert_rule_format
from siem_integration import send_to_siem

@click.group()
def cli():
    """CLI for managing rule engine."""
    pass

@cli.command()
@click.argument('rule_path')
def load(rule_path):
    """Load and validate rules from a file."""
    load_rules(rule_path)

@cli.command()
@click.argument('log_file')
def execute(log_file):
    """Execute rules on logs."""
    execute_rules(log_file)

@cli.command()
@click.argument('rule_path')
@click.argument('format')
def convert(rule_path, format):
    """Convert rule from one format to another."""
    convert_rule_format(rule_path, format)

@cli.command()
@click.argument('rule_path')
def send(rule_path):
    """Send rules to SIEM."""
    send_to_siem(rule_path)

if __name__ == "__main__":
    cli()
