# rule-engine

## Project Structure

The project is organized as follows:

```
rule-engine/
│
├── src/rule_engine/
│   ├── api/
│   │   ├── helpers/
│   │   │   ├── utils.py
│   │   │   └── validation.py
│   │   ├── rule_conversion_api.py
│   │   ├── rule_execution_api.py
│   │   ├── rule_parser_api.py
│   │   └── siem_integration_api.py
│   │
│   ├── cli/
│   │   ├── main.py
│   │   └── rule_conversion.py
│   │
│   ├── engine/
│   │   ├── converters/
│   │   │   ├── rule_converter.py
│   │   │   ├── sigma_to_wazuh.py
│   │   │   ├── sigma_to_yara.py
│   │   │   └── wazuh_to_sigma.py
│   │   ├── executors/
│   │   │   └── executors.py
│   │   ├── integration/
│   │   │   ├── api_integration.py
│   │   │   ├── common.py
│   │   │   ├── elastic_integration.py
│   │   │   ├── integration.py
│   │   │   ├── splunk_integration.py
│   │   │   └── wazuh_integration.py
│   │   └── parsers/
│   │       ├── common.py
│   │       ├── load_rules.py
│   │       ├── sigma_parser.py
│   │       ├── wazuh_parser.py
│   │       └── yara_parser.py
│   │
│   └── __init__.py
│
├── rules/
│   ├── sigma/
│   ├── wazuh/
│   └── yara/
│
├── tests/
│   ├── opendxl_to_sigma.py
│   ├── test_parsers.py
│   ├── test_sigma_to_wazuh.py
│   └── test_sigma_to_yara.py
│
├── pyproject.toml
├── uv.lock
├── Dockerfile
├── Makefile
└── README.md
```

## Description

This project is a rule engine that supports multiple rule formats including Yara, Sigma, and Wazuh. It provides APIs for rule conversion, execution, and validation, as well as a CLI for managing rules.

## Installation

This project uses [UV](https://docs.astral.sh/uv/) as the package manager.

1. Clone the repository:
   ```
   git clone https://github.com/khulnasoft/rule-engine.git
   ```
2. Navigate to the project directory:
   ```
   cd rule-engine
   ```
3. Install dependencies:
   ```
   uv sync
   ```

## Usage

### API

To run the API server:
```
make run
```
or
```
uv run flask run --host=0.0.0.0 --port=5000
```

### CLI

To use the CLI, run:
```
uv run rule-engine
```

### Tests

To run tests:
```
make test
```
or
```
uv run pytest
```

## Development

- `make venv` — Create virtual environment and install dependencies
- `make install` — Install dependencies
- `make run` — Run the Flask API server
- `make test` — Run tests
- `make docker-build` — Build Docker image
- `make clean` — Clean up virtual environment

## Docker

Build and run the Docker image:
```
make docker-build
make docker-run
```

## Documentation

For detailed code review guidelines, please refer to the [CODE_REVIEW_GUIDELINES.md](CODE_REVIEW_GUIDELINES.md) file.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.
