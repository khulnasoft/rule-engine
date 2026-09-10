# Rule Engine Implementation & Improvement Plan

## Current State Assessment

The project has a framework skeleton with real rule data (726 YARA, 2,983 Sigma, 133 Wazuh rules) but critical gaps in implementation across parsers, converters, executors, integrations, CLI, API, and tests.

---

## Gap Analysis

### 1. Parsers

| Gap | Details |
|-----|---------|
| YARA not dispatched in `load_rules.py` | `load_rule()` has duplicate definitions, YARA files silently fail |
| YARA parser lacks `meta`, `import`, complex `condition` | Only regex-extracts strings and rule name |
| Wazuh parser missing key elements | No `if_sid`, `if_group`, `if_matched_group`, `frequency`, `timeframe`, `mitre`, `options` |
| Sigma parser is basic YAML load | No validation of Sigma-specific syntax (field operators, condition logic) |
| No unified parser interface | Three separate parsers with no common abstraction |

### 2. Converters

| Conversion | Status |
|------------|--------|
| YARA → Sigma | Basic (strings only) |
| YARA → Wazuh | **Does not exist** |
| Sigma → YARA | Basic (CommandLine only) |
| Sigma → Wazuh | Basic (hardcoded fields) |
| Wazuh → Sigma | Basic (hardcoded fields) |
| Wazuh → YARA | **Does not exist** |
| YARA → Wazuh | **Does not exist** |
| Bidirectional Sigma ↔ YARA ↔ Wazuh | No unified `convert_rule()` pipeline |

### 3. Executors

| Gap | Details |
|-----|---------|
| No actual rule engine | `match_rule()` does substring matching only |
| No YARA matching engine | Should use `yara` Python library |
| No Sigma condition evaluator | Should evaluate Sigma `selection`/`filter`/`condition` |
| No Wazuh rule matching | Should handle `if_sid`, `if_group`, `if_matched_group`, frequency/timeframe |
| `rule_execution_api.py` broken | Imports from non-existent `rule_engine.engine.execution` |

### 4. Integrations

| Gap | Details |
|-----|---------|
| Missing `siem_integration.py` | `siem_integration_api.py` imports from non-existent module |
| `api_integration.py` is standalone | Separate Flask app, not integrated with main `app.py` |
| Duplicate `send_to_wazuh()` | Exists in both `integration.py` and `wazuh_integration.py` |
| No actual SIEM connectors | All SIEM functions are stubs or minimal HTTP calls |

### 5. CLI Commands

| Command | Status |
|---------|--------|
| `load` | Works for YAML/XML only, no YARA |
| `execute` | **Stub** -- just prints log lines |
| `convert` | **Stub** -- just prints format string |
| `send` | **Stub** -- just prints "Sending to SIEM" |

### 6. API Endpoints

| Endpoint | Gap |
|----------|-----|
| `POST /api/rule_parser/validate` | No YARA validation, no Sigma field operator validation |
| `POST /api/rule_execution/execute` | References non-existent `rule_engine.engine.execution` module |
| `POST /api/rule_conversion/convert` | Only Sigma→YARA/Wazuh, no bidirectional |
| `POST /api/siem_integration/send` | References non-existent `rule_engine.engine.integration.siem_integration` |

### 7. Tests

| Gap | Details |
|-----|---------|
| `test_parsers.py` | Completely broken — calls undefined `parse_rule()` |
| `test_sigma_to_wazuh.py` | References non-existent `'path/to/sample_sigma_rule.yml'` |
| `test_sigma_to_yara.py` | References non-existent `'path/to/sample_sigma_rule.yml'` |
| No YARA tests | No parser, converter, or executor tests |
| No Wazuh tests | No parser, converter, or executor tests |
| No executor tests | No tests for rule matching |
| No CLI tests | No click command tests |
| `opendxl_to_sigma.py` | Misplaced source code in tests/ |

---

## Implementation Plan

### Phase 1: Fix Foundation (Week 1)

**1.1 Fix `load_rules.py` — Remove duplicate `load_rule()` and add YARA support**
- Remove duplicate function definition
- Add `.yar`/`.yara` extension dispatch to `yara_parser.py`
- Create unified `RuleLoader` class that wraps all three parsers

**1.2 Fix broken imports across API and executor modules**
- Fix `rule_execution_api.py`: change `from rule_engine.engine.execution import execute_rules` → `from rule_engine.engine.executors import execute_rules`
- Fix `siem_integration_api.py`: create `src/rule_engine/engine/integration/siem_integration.py` with `send_to_siem()` function
- Fix all imports in `src/rule_engine/api/` to match actual module paths

**1.3 Create shared `Rule` dataclass**
- Define `Rule` model with fields for all three formats (YARA, Sigma, Wazuh)
- Create `RuleFormat` enum (`YARA`, `SIGMA`, `WAZUH`)
- Place in `src/rule_engine/engine/common.py` or new `src/rule_engine/engine/models.py`

**1.4 Fix `__init__.py` files to export public API**
- Add proper imports to `engine/__init__.py`, `engine/converters/__init__.py`, `engine/parsers/__init__.py`, `engine/executors/__init__.py`, `engine/integration/__init__.py`

### Phase 2: Parsers (Week 2)

**2.1 Enhance YARA Parser**
- Parse `meta` blocks as dict
- Parse `import` statements
- Parse `strings` section (regex, hex, ASCII)
- Parse `condition` as AST/string representation
- Handle `filesize`, `pe.*`, `uint16()` etc.

**2.2 Enhance Wazuh Parser**
- Parse `if_sid`, `if_group`, `if_matched_group`
- Parse `frequency`, `timeframe`
- Parse `mitre` section (tactic, technique)
- Parse `options` section
- Parse `group`, `rules_re`/`rules_ids`
- Add null-safety for missing XML elements

**2.3 Enhance Sigma Parser**
- Validate Sigma-specific field operators (`endswith`, `contains`, `all`, `re`)
- Parse `filter`, `condition` sections
- Detect `Timeline` fields
- Validate `logsource` product/category

**2.4 Create `RuleLoader` unified interface**
- `RuleLoader.load(path)` → auto-detects format and delegates
- `RuleLoader.validate(rule)` → validates format-specific required fields
- Support batch loading from `rules/` directory

### Phase 3: Converters (Week 3)

**3.1 Build YARA → Wazuh Converter**
- Extract YARA rule name → Wazuh `<group>` and `<id>`
- Extract YARA strings → Wazuh `<match>`/`<regex>` fields
- Extract YARA `condition` → Wazuh `<match>` expression
- Map YARA `meta` fields → Wazuh `<group>` and `<description>`

**3.2 Build Wazuh → YARA Converter**
- Extract Wazuh `if_sid` → YARA rule name
- Extract Wazuh `match`/`regex` → YARA strings
- Extract Wazuh `description` → YARA `meta.description`
- Map Wazuh `group` → YARA `meta.category`

**3.3 Improve Sigma → YARA Converter**
- Handle all Sigma field operators (`endswith`, `contains`, `re`, etc.)
- Map Sigma `selection`/`filter`/`condition` → YARA `strings`/`condition`
- Support non-`CommandLine` fields (e.g., `TargetImage`, `Registry`)

**3.4 Improve Sigma → Wazuh Converter**
- Map all Sigma detection fields to Wazuh XML `<field>` elements
- Handle `filter` and `condition` logic
- Map `logsource` → Wazuh `<group>` and metadata

**3.5 Build Unified `convert_rule()` pipeline**
- `convert_rule(rule, from_format, to_format)` dispatcher
- Support all 6 conversion directions
- Return converted `Rule` object or dict

### Phase 4: Executors (Week 4)

**4.1 Integrate YARA Python Library**
- Add `yara` as dependency in `pyproject.toml`
- Create `YaraRuleExecutor` class that compiles and matches YARA rules against files
- Support file-based matching with `yara.compile()`

**4.2 Build Sigma Condition Evaluator**
- Create `SigmaConditionEvaluator` class
- Evaluate Sigma `selection`/`filter`/`condition` against log events
- Support all Sigma field operators
- Handle boolean logic in `condition` field

**4.3 Build Wazuh Rule Matcher**
- Create `WazuhRuleMatcher` class
- Match events against Wazuh `if_sid`, `if_group`, `if_matched_group`
- Implement frequency/timeframe logic
- Support `regex`/`match` field matching

**4.4 Create Unified `RuleExecutor`**
- `RuleExecutor.execute(rule, log_event)` → dispatches to format-specific executor
- `RuleExecutor.execute_on_log(rule, log_file)` → iterates log file lines
- Return match results with metadata

**4.5 Fix `rule_execution_api.py`**
- Update import to `from rule_engine.engine.executors import execute_rules`
- Implement actual execution logic in API endpoint

### Phase 5: Integrations (Week 5)

**5.1 Create `siem_integration.py`**
- Implement `send_to_siem()` function
- Support Splunk HEC, Elasticsearch, Wazuh REST API
- Add error handling and retry logic
- Add `send_to_splunk()`, `send_to_elastic()`, `send_to_wazuh()` wrappers

**5.2 Fix `siem_integration_api.py`**
- Update import to use new `siem_integration.py`
- Implement actual SIEM sending in API endpoint

**5.3 Integrate `api_integration.py`**
- Merge Flask app from `api_integration.py` into main `app.py`
- Add `/validate_rule` endpoint to main app
- Remove standalone Flask app

**5.4 Remove duplicate `send_to_wazuh()`**
- Consolidate into `siem_integration.py`
- Update all references

### Phase 6: CLI (Week 6)

**6.1 Implement `load` command**
- Add YARA file support
- Add validation output
- Show rule metadata (format, name, fields)

**6.2 Implement `execute` command**
- Wire to `RuleExecutor`
- Accept log file path
- Output matched rules with details

**6.3 Implement `convert` command**
- Wire to `convert_rule()` pipeline
- Accept source rule path and target format
- Output converted rule to stdout or file

**6.4 Implement `send` command**
- Wire to `send_to_siem()`
- Accept SIEM type (splunk/elastic/wazuh)
- Handle configuration via env vars or config file

### Phase 7: Tests (Week 7)

**7.1 Fix `test_parsers.py`**
- Rewrite with proper imports and test data
- Test all three format parsers
- Use inline test data instead of file paths

**7.2 Fix `test_sigma_to_wazuh.py` and `test_sigma_to_yara.py`**
- Use inline test data instead of `'path/to/sample_sigma_rule.yml'`
- Add proper assertions

**7.3 Add YARA parser/converter tests**
- Test YARA parsing of `meta`, `import`, `strings`, `condition`
- Test YARA → Sigma conversion
- Test YARA → Wazuh conversion

**7.4 Add Wazuh parser/converter tests**
- Test Wazuh parsing of `if_sid`, `frequency`, `timeframe`, `mitre`
- Test Wazuh → Sigma conversion
- Test Wazuh → YARA conversion

**7.5 Add executor tests**
- Test YARA rule matching against sample events
- Test Sigma condition evaluation
- Test Wazuh `if_sid` matching

**7.6 Add CLI tests**
- Use `click.testing.CliRunner`
- Test all four commands (`load`, `execute`, `convert`, `send`)

**7.7 Move `opendxl_to_sigma.py`**
- Move from `tests/` to `src/rule_engine/engine/converters/` or `src/rule_engine/engine/integration/`

### Phase 8: Dependencies & Configuration (Week 8)

**8.1 Add `yara` dependency**
- Add `yara-python` to `pyproject.toml` dependencies
- Run `uv add yara-python`
- Update `uv.lock`

**8.2 Remove `fastapi` dependency**
- API uses Flask, not FastAPI
- Remove from `pyproject.toml`
- Run `uv remove fastapi`

**8.3 Add `pyyaml` (already present)**
- Already in dependencies, verify it's used consistently

**8.4 Add `requests` (already present)**
- Already in dependencies, verify it's used consistently

**8.5 Add `click` (already present)**
- Already in dependencies

---

## Priority Matrix

| Priority | Item | Impact | Effort |
|----------|------|--------|--------|
| **P0** | Fix broken imports (`engine.execution` → `engine.executors`) | Unblocks all API and execution | Low |
| **P0** | Fix `siem_integration_api.py` broken import | Unblocks SIEM API endpoint | Low |
| **P0** | Fix duplicate `load_rule()` in `load_rules.py` | Unblocks rule loading | Low |
| **P1** | Add YARA dispatch to `load_rules.py` | Enables YARA rule loading | Medium |
| **P1** | Create `Rule` dataclass and `RuleFormat` enum | Foundation for all improvements | Medium |
| **P1** | Create `siem_integration.py` module | Unblocks SIEM integration | Medium |
| **P2** | Enhance Wazuh parser (`if_sid`, `frequency`, `timeframe`) | Full Wazuh rule support | Medium |
| **P2** | Build YARA → Wazuh converter | Complete bidirectional conversion | High |
| **P2** | Build Wazuh → YARA converter | Complete bidirectional conversion | High |
| **P3** | Integrate YARA Python library into executor | Real YARA matching | High |
| **P3** | Build Sigma condition evaluator | Real Sigma execution | High |
| **P3** | Build Wazuh rule matcher | Real Wazuh execution | High |
| **P4** | Implement all CLI commands (`execute`, `convert`, `send`) | Full CLI functionality | Medium |
| **P4** | Fix and expand test suite | Test coverage | Medium |
| **P5** | Remove `fastapi` dependency | Clean dependencies | Low |
| **P5** | Integrate `api_integration.py` into main app | Clean architecture | Low |

---

## Architecture Target

```
src/rule_engine/
├── __init__.py              # main() entry point
├── engine/
│   ├── __init__.py          # exports Rule, RuleFormat, RuleLoader, RuleExecutor
│   ├── models.py            # Rule dataclass, RuleFormat enum
│   ├── parsers/
│   │   ├── __init__.py      # exports parse_yara, parse_sigma, parse_wazuh, load_rule
│   │   ├── base.py          # BaseParser abstract class
│   │   ├── yara_parser.py   # Full YARA parser (meta, import, strings, condition)
│   │   ├── sigma_parser.py  # Enhanced Sigma parser (operators, conditions)
│   │   ├── wazuh_parser.py  # Enhanced Wazuh parser (if_sid, frequency, mitre)
│   │   └── load_rules.py    # Unified RuleLoader with format detection
│   ├── converters/
│   │   ├── __init__.py      # exports convert_rule, all converters
│   │   ├── base.py          # BaseConverter abstract class
│   │   ├── yara_to_sigma.py # Enhanced
│   │   ├── yara_to_wazuh.py # NEW
│   │   ├── sigma_to_yara.py # Enhanced
│   │   ├── sigma_to_wazuh.py # Enhanced
│   │   ├── wazuh_to_sigma.py # Enhanced
│   │   ├── wazuh_to_yara.py # NEW
│   │   └── common.py
│   ├── executors/
│   │   ├── __init__.py      # exports execute_rules, RuleExecutor
│   │   ├── base.py          # BaseExecutor abstract class
│   │   ├── yara_executor.py # Uses yara-python library
│   │   ├── sigma_executor.py # Evaluates Sigma conditions
│   │   ├── wazuh_executor.py # Matches if_sid/frequency/timeframe
│   │   └── executors.py     # Legacy (deprecated or updated)
│   ├── integration/
│   │   ├── __init__.py      # exports send_to_siem, send_to_splunk, etc.
│   │   ├── siem_integration.py  # NEW - unified SIEM connector
│   │   ├── splunk_integration.py
│   │   ├── elastic_integration.py
│   │   ├── wazuh_integration.py
│   │   └── common.py
├── api/
│   ├── __init__.py
│   ├── app.py              # Main Flask app with all blueprints
│   ├── rule_parser_api.py
│   ├── rule_execution_api.py  # Fixed imports
│   ├── rule_conversion_api.py # Enhanced with bidirectional support
│   ├── siem_integration_api.py # Fixed imports
│   └── helpers/
│       ├── __init__.py
│       ├── utils.py
│       └── validation.py     # Actual validation logic
├── cli/
│   ├── __init__.py
│   ├── main.py             # Complete CLI with all commands implemented
│   ├── rule_parser.py
│   ├── rule_execution.py    # Implemented
│   ├── rule_conversion.py   # Implemented
│   ├── siem_integration.py  # Implemented
│   └── utils.py
└── utils.py                # Shared utilities
```

---

## Rule Data Utilization

The project already has extensive rule data that needs to be leveraged:

| Directory | Count | Usage Plan |
|-----------|-------|------------|
| `rules/yara/` | 726 files | Load and validate all YARA rules using enhanced parser |
| `rules/sigma/` | 2,983 files | Load and validate all Sigma rules using enhanced parser |
| `rules/wazuh/` | 133 files | Load and validate all Wazuh rules using enhanced parser |
| `rules/` | application/ | Application-specific rules |

All three format parsers should support batch loading from these directories.

---

## Comprehensive Detection Rule Expansion

Expand the repository into a multi-format detection corpus with native Sigma, YARA, ClamAV, and Sysmon support. The existing `rules/wazuh/0320-clam_av_rules.xml`, `rules/wazuh/0330-sysmon_rules.xml`, and `rules/wazuh/0595-win-sysmon_rules.xml` provide starting coverage, but they should be treated as source material for dedicated format-aware rules rather than as substitutes for native parsers.

### Format Coverage

| Format | Target role | Required repository layout |
|--------|-------------|----------------------------|
| Sigma | Log and telemetry detections across Windows, Linux, macOS, cloud, network, identity, and application sources | `rules/sigma/<platform>/<logsource>/` |
| YARA | File, memory, malware family, packer, document, web shell, and threat artifact detection | `rules/yara/<domain>/` |
| ClamAV | Portable signature coverage for files, archives, documents, scripts, and malware artifacts | `rules/clamav/<domain>/` |
| Sysmon | Windows endpoint telemetry and event-specific detections | `rules/sysmon/<event_id>/<domain>/` |

### Sigma Coverage Domains

Prioritize rules for the following domains, with each rule mapped to a log source, ATT&CK technique where applicable, severity, and test event:

- Process creation, scripting, LOLBins, interpreter abuse, and suspicious parent-child relationships
- File creation, deletion, rename, permission changes, alternate data streams, and temporary paths
- Registry, services, scheduled tasks, WMI, COM hijacking, startup folders, and other persistence
- PowerShell, command shell, Python, JavaScript, VBScript, Office macros, and signed binary proxy execution
- Credential access, token abuse, password stores, LSASS access, browser theft, and authentication anomalies
- Defense evasion, tampering, log clearing, masquerading, obfuscation, timestomping, and security-tool changes
- Discovery, lateral movement, remote services, SMB, RDP, SSH, WinRM, cloud control planes, and container orchestration
- DNS, HTTP, TLS, proxy, tunneling, beaconing, exfiltration, and suspicious external service interaction
- Cloud identity, IAM changes, audit-log manipulation, storage access, serverless execution, and SaaS abuse
- Web server, database, email, VPN, firewall, identity provider, and application-specific events
- The requested content categories: anti-debug/anti-VM, capabilities, CVEs, crypto, exploit kits, malicious documents, malware, packers, and web shells

Every Sigma rule should include valid `title`, `id`, `status`, `description`, `author`, `date`, `logsource`, `detection`, `level`, and `tags` metadata. Rules with unsupported field modifiers or ambiguous conditions must fail validation with a useful reason.

### YARA Coverage Domains

Organize native YARA rules by detection purpose and require metadata for family, platform, file type, source, confidence, references, and category:

- Malware families, loaders, droppers, implants, ransomware, cryptominers, and post-exploitation tools
- Packers, protectors, obfuscation, anti-analysis, anti-debug, anti-VM, and embedded configuration
- Office, PDF, archive, script, shortcut, HTML, email, and other malicious document artifacts
- Web shells, server-side scripts, exploit-kit payloads, and web delivery components
- Credential stealers, keyloggers, browser data theft, remote access tools, and hacking utilities
- PE, ELF, Mach-O, .NET, Java, firmware, mobile, and memory-oriented artifacts
- CVE-specific payloads, exploit artifacts, rootkits, bootkits, and persistence components
- Network indicators, C2 configurations, encoded domains, wallet addresses, and staging artifacts

Use valid YARA syntax, stable rule names, bounded regex and string sizes, and explicit `condition` intent. Rules should include positive and negative fixtures where practical to reduce noisy signatures.

### ClamAV Coverage

Create a native ClamAV signature pipeline for signatures that can be represented safely in ClamAV formats:

- Start with logical signatures for stable file and byte-pattern indicators.
- Add hash, container, HTML, PE, and script signatures only when the detection is deterministic and maintainable.
- Preserve source, family, category, minimum ClamAV version, and false-positive notes as structured metadata.
- Validate signatures with an installed ClamAV toolchain and scan clean, positive, archive, and malformed fixtures.
- Do not mechanically translate complex YARA conditions into weak ClamAV patterns; retain the original YARA rule when fidelity cannot be preserved.

### Sysmon Coverage

Add native Sysmon rule definitions and event fixtures for the major Sysmon event IDs:

- 1 Process Create, 2 File creation time changed, 3 Network Connection, and 5 Process Terminated
- 6 Driver Loaded, 7 Image Loaded, 8 CreateRemoteThread, and 9 RawAccessRead
- 10 Process Access, 11 File Create, 12-14 Registry events, and 15 Alternate Data Stream
- 17-18 Named Pipe events, 19-21 WMI activity, 22 DNS Query, and 23-26 file and process cleanup events
- 27-29 executable and file blocking events where supported by the deployed Sysmon version

Each Sysmon rule must declare its event ID, included fields, excluded fields, condition semantics, minimum Sysmon version, and expected event fixture. Keep noisy informational baselines separate from high-confidence threat detections. Map equivalent Sysmon detections to Sigma where possible without losing event-specific fields.

### Shared Expansion Work

**D1. Establish format schemas and loaders**
- Add `ClamAV` and `Sysmon` values to `RuleFormat` and implement native parsers, validators, and batch loaders.
- Extend the common rule model with format-specific payloads while preserving normalized name, ID, status, severity, category, tags, references, and provenance.
- Detect duplicate IDs, duplicate signatures, conflicting metadata, unsupported syntax, and orphaned references.

**D2. Import and normalize existing coverage**
- Parse the existing ClamAV and Sysmon-related Wazuh rules into normalized source records.
- Link imported records back to their original Wazuh file and rule ID.
- Generate native ClamAV and Sysmon candidates only after semantic review; retain an explicit `derived_from` relationship.
- Avoid duplicating equivalent Sigma, YARA, Wazuh, ClamAV, and Sysmon rules unless their execution context materially differs.

**D3. Build rule production batches**
- Create one reviewed batch per format and coverage domain, starting with high-value Windows process, script, network, persistence, malware, CVE, and web shell detections.
- Require a rule manifest containing source, owner, date, category, ATT&CK mapping, supported platforms, confidence, and test fixture paths.
- Prefer small, reviewable batches over bulk generated rules so false positives and unsupported translations are visible.

**D4. Add cross-format conversion carefully**
- Support Sigma <-> Sysmon mappings for compatible Windows event detections.
- Support YARA -> ClamAV candidates only for provably equivalent byte or file indicators.
- Preserve source rules when a conversion loses condition logic, context, event fields, or execution semantics.
- Mark generated rules with provenance and require manual approval before they enter the active corpus.

**D5. Test and measure quality**
- Add syntax and schema validation for every format in CI.
- Add positive, negative, malformed-input, and regression fixtures per detection family.
- Run duplicate, coverage, and category reports by format, platform, event source, ATT&CK technique, and confidence.
- Track false-positive findings, stale rules, unsupported versions, missing metadata, and untested rules as actionable report items.
- Require all new rules to pass deterministic local tests without network access.

**Suggested rollout:** implement D1 first, import existing Wazuh coverage in D2, deliver reviewed Sigma and YARA batches alongside native ClamAV and Sysmon pilots in D3, then enable D4 conversions and D5 CI enforcement.

---

## Category Taxonomy & Classification Plan

Categories should be a shared metadata layer across YARA, Sigma, and Wazuh. They should not replace the existing platform/logsource directories or MITRE ATT&CK tags. A rule may have one primary category and multiple secondary categories; category assignment must remain traceable to explicit metadata or a documented classification decision.

### Requested Categories

Add the following canonical categories to the category registry:

- **Anti-debug/Anti-VM** - debugger, sandbox, virtual-machine, and analysis-environment detection or evasion
- **Capabilities** - rules describing malware or tooling capabilities that do not fit a more specific behavior category
- **CVE Rules** - rules explicitly tied to one or more CVE identifiers
- **Crypto** - cryptominers, cryptocurrency theft, cryptographic misuse, and crypto-related tooling
- **Exploit Kits** - exploit-kit infrastructure, landing pages, payload delivery, and kit artifacts
- **Malicious Documents** - weaponized office, PDF, archive, script, and other document-based content
- **Malware** - malware family, sample, artifact, or behavior detections without a narrower category
- **Packers** - packers, protectors, obfuscators, and packed-binary indicators
- **WebShells** - web shells and server-side script persistence or command execution
- **Deprecated** - rules retained for compatibility but no longer recommended for active use

### Additional Categories to Add

Prioritize these complementary categories because they are common in the existing rule corpus and useful for filtering:

- **Persistence**
- **Privilege Escalation**
- **Defense Evasion**
- **Credential Access**
- **Discovery**
- **Execution**
- **Initial Access**
- **Lateral Movement**
- **Command and Control**
- **Exfiltration**
- **Impact**
- **Ransomware**
- **Phishing**
- **Vulnerability Scanning**
- **Living off the Land**
- **Indicators of Compromise**
- **Threat Intelligence**

ATT&CK-aligned behavior categories should be mapped from `attack.*` tags where possible. Content categories such as **Malicious Documents**, **Packers**, and **WebShells** should remain independent from ATT&CK tactics so a rule can carry both kinds of classification.

### Implementation Steps

**C1. Define the category registry**
- Add a canonical slug, display name, description, and lifecycle status for every category.
- Add aliases and normalization rules for spelling and legacy names (for example, `webshell`, `web-shell`, and `web_shell` -> `webshells`).
- Add `Category` and `CategoryStatus` models and expose the registry from the public engine API.

**C2. Extend the common rule model and parsers**
- Add `primary_category`, `categories`, and `category_source` to the shared `Rule` model.
- Parse existing Sigma `tags`, `status`, `references`, and `logsource` values without losing the original metadata.
- Extract CVE identifiers from tags, titles, descriptions, and references into the **CVE Rules** category and a normalized `cves` field.
- Support equivalent category metadata in YARA `meta` and Wazuh rule metadata.

**C3. Build deterministic classification**
- Apply explicit rule metadata first, then CVE extraction, ATT&CK mapping, and narrowly scoped content heuristics.
- Record the reason and source for each assignment; ambiguous rules should be marked `needs-review` rather than silently forced into a category.
- Reserve **Deprecated** for lifecycle metadata or an explicit deprecation decision, never for an arbitrary parser failure.

**C4. Classify and migrate the existing corpus**
- Generate a dry-run report with counts by format, category, confidence, and unclassified rule.
- Review high-impact and low-confidence assignments before writing metadata back to source rules.
- Preserve original files and IDs; add only normalized category metadata and migration documentation.
- Ensure a rule can belong to multiple categories while having exactly one primary category.

**C5. Add category-aware APIs and CLI**
- Add category filters to rule loading, conversion, execution, and batch validation.
- Add `list-categories` and category filtering to the CLI, plus JSON output for automation.
- Add API endpoints or query parameters to list categories and retrieve rules by category, status, format, and confidence.

**C6. Validate and test the taxonomy**
- Test canonicalization, aliases, multi-category rules, CVE extraction, deprecated handling, and unknown-category rejection.
- Add fixture tests for each requested category and representative additional category.
- Add a corpus validation test that reports unclassified or invalid-category rules without making the full suite depend on network access.

**Suggested rollout:** implement C1-C2 first, run C3 in report-only mode, review the C4 report, then enable C5 filters and enforce C6 validation in CI.

---

## Dependency Changes

### Add
- `yara-python` — For YARA rule execution

### Remove
- `fastapi` — Not used (API uses Flask)

### Keep
- `click` — CLI framework
- `pyyaml` — YAML/Sigma parsing
- `requests` — HTTP calls to SIEMs
- `flask` — API framework
- `pytest` — Testing
