# SBOM Training Process

This document outlines the process for training a model on SBOM (Software Bill of Materials) policy generation, separate from the SLSA attestation training.

## Overview

The SBOM training process follows the same workflow as attestation training but uses SBOM-specific data structures, test cases, and training scripts. This keeps the two training processes completely separated and reproducible.

**Key Innovation: Execution-Based Test Generation**

The SBOM training process uses an **execution-based approach** for generating validation tests. This means we actually execute the Rego rules with test data using OPA to verify correctness, rather than relying solely on pattern matching. This ensures:

- **100% accuracy**: Tests are verified by running the rule
- **Self-correcting**: If rules change, test generation adapts automatically
- **No false positives**: We know exactly what the rule does because we test it
- **Reliable**: If a test is generated, it's guaranteed to be correct

## Directory Structure

```
rego-training/
├── sbom_data/                          # SBOM-specific data files
│   ├── test_case_definitions.json     # SBOM test case definitions
│   ├── comprehensive_test_cases.json  # SBOM comprehensive test cases
│   └── qwen3-sbom-training-data.jsonl # SBOM training data output
├── sbom_rego_rules/                    # SBOM-specific Rego rule files
│   └── *.rego                         # Individual SBOM policy rules
├── docs/
│   └── sbom-structure-training-data.md # SBOM structure documentation
└── scripts/core/
    ├── generate_sbom_training_from_rules.py  # SBOM training data generator
    ├── generate_sbom_validation_tests_execute.py  # Execution-based test generator (recommended)
    └── generate_sbom_validation_tests.py  # Legacy pattern-matching generator
```

## Process Overview

The SBOM training process mirrors the attestation training process:

1. **Test Case Definition** - Define SBOM requirements and test cases
2. **Rego Rule Generation** - Create Rego rules from SBOM requirements
3. **Validation Test Generation** - Generate tests using execution-based approach
4. **Rego Test File Generation** - Create OPA-compliant test files
5. **Validation** - Validate rules against SBOM test cases
6. **Training Data Generation** - Convert validated rules to training data
7. **Model Fine-tuning** - Train Qwen3 model on SBOM training data
8. **Deployment** - Deploy model for use

## Phase 1: Test Case Definition

### Purpose
Define natural language requirements and corresponding test cases for SBOM validation rules.

### Data Files
- **`sbom_data/comprehensive_test_cases.json`** - Comprehensive SBOM test cases with natural language, Rego code, and test data
- **`sbom_data/test_case_definitions.json`** - SBOM test case definitions with validation tests

### Process

1. **Define Requirements**: Create natural language requirements for SBOM policy validation
   - Example: "Verify the SPDX SBOM contains packages."
   - Example: "Verify no packages in the SPDX SBOM have version '(devel)'."
   - Example: "Verify all packages in the SPDX SBOM have allowed external references."

2. **Generate Test Cases**: Create test cases manually or use `generate_sbom_test_cases.py`
   - Natural language descriptions
   - Rego code (if available)
   - Test data (positive and negative cases)
   - Keys used in the rule (e.g., `input.attestations`, `statement.predicateType`, `statement.predicate.packages`, `pkg.versionInfo`)

3. **Generate Validation Tests**: Convert test cases to validation format using execution-based approach
   - Positive tests (should_deny: true) - when condition is violated
   - Negative tests (should_deny: false) - when condition is met

### Output
- `sbom_data/comprehensive_test_cases.json` - Source test cases
- `sbom_data/test_case_definitions.json` - Validation-ready test cases

## Phase 2: Rego Rule Generation (TDD Workflow)

### Purpose
Create Rego rule files that make the tests pass (TDD workflow).

**Key Change**: Rules are generated to satisfy tests, not the other way around.

### Script: `generate_sbom_rego_rules.py`

This script supports both TDD and legacy workflows:

**TDD Workflow:**
- Reads from `sbom_data/requirements.json` + `sbom_data/test_case_definitions.json`
- Rules should be generated (model or manual) to make tests pass
- Currently falls back to `comprehensive_test_cases.json` if rego_code exists there

**Legacy Workflow:**
- Reads from `sbom_data/comprehensive_test_cases.json`
- Extracts existing rego_code

**Usage:**
```bash
python3 scripts/core/generate_sbom_rego_rules.py
```

**Output:**
- `sbom_rego_rules/*.rego` - SBOM Rego rule files (one per requirement)

### Process

1. **Generate Rego Files**: 
   - **TDD**: Generate rules from requirements + tests (model or manual)
   - **Legacy**: Extract Rego code from comprehensive_test_cases.json
   - Include METADATA annotations with natural language descriptions
   - Use pure Rego (no library imports)
   - Access SBOMs directly from `input.attestations` by checking `predicateType`
   - Use proper SBOM paths (e.g., `statement.predicate.packages`, `pkg.externalRefs`)
   - **Rules must make tests pass** (TDD principle)

## Phase 3: Validation Test Generation (TDD Workflow)

### Purpose
Generate validation test definitions from requirements (TDD workflow).

**Key Change**: Tests are now generated from requirements only, not from rego_code. Rules will be generated later to make tests pass.

### Script: `generate_sbom_validation_tests_execute.py`

This script uses an **execution-based approach** to generate validation tests. It actually executes the Rego rule with test data using OPA to verify correctness.

**Key Features (TDD Workflow):**
- **Pattern-based generation**: Generates test data from requirements (natural_language, keys_used) only
- **No rego_code needed**: Tests are generated before rules exist
- Generates both positive (should deny) and negative (should pass) test cases
- Uses intelligent pattern matching on natural language and keys_used to generate test variations
- **Execution verification**: After rules are generated, they can be verified by execution (separate step)
- Supports 15+ patterns including:
  - Collection emptiness (packages, components, files)
  - Field presence/absence
  - Format validation
  - Empty string checks
  - Uniqueness/duplicate detection
  - Count/at least validation
  - Checksum validation
  - External reference validation (PURL, CPE)
  - Startswith/contains function validation
  - Conditional validation
  - Nested field validation
  - Timestamp validation

**Why TDD Workflow?**
- **Tests define contract**: Tests specify what the rule should do before implementation exists
- **No circular dependency**: Tests don't depend on rules, rules depend on tests
- **Better for model training**: Can train on requirements → rules (with tests as validation)
- **Clear separation**: Requirements, tests, and implementation are separate
- **Execution verification**: After rules are generated, execute them to verify correctness (separate validation step)

**Usage:**
```bash
python3 scripts/core/generate_sbom_validation_tests_execute.py
```

**How It Works (TDD):**
1. **Read Requirements**: Loads `sbom_data/requirements.json` (natural_language, keys_used, type only)

2. **Generate Test Variations**: Creates test data variations based on:
   - Natural language descriptions
   - Keys used in the requirement
   - Pattern matching (startswith, contains, count, etc.)

3. **Classify Tests**: Determines if each variation should deny or pass based on:
   - Variation name patterns (no_, missing_, empty_ → should deny)
   - Natural language context

4. **Output Test Definitions**: Creates `test_case_definitions.json` with test data and expected outcomes

**Note**: Execution verification happens AFTER rules are generated (see Phase 5: Validation)

**Output:**
- `sbom_data/test_case_definitions.json` - JSON test case definitions with input data and expected outcomes
- Tests are generated from requirements only (no rego_code needed)

**Files:**
- **Input**: `sbom_data/requirements.json` (TDD workflow) or `sbom_data/comprehensive_test_cases.json` (legacy)
- **Output**: `sbom_data/test_case_definitions.json`

## Phase 4: Rego Test File Generation

### Purpose
Generate OPA-compliant Rego test files (`_test.rego`) from validation test definitions.

### Script: `generate_sbom_rego_tests.py`

This script reads from `sbom_data/test_case_definitions.json` and generates OPA-compliant test files.

**Usage:**
```bash
python3 scripts/core/generate_sbom_rego_tests.py
```

**Output:**
- `sbom_rego_rules/*_test.rego` - OPA-compliant test files (one per rule)

## Phase 5: Validation (Execution Verification)

### Purpose
Validate SBOM Rego rules against test cases to ensure correctness (TDD verification step).

### Process

1. **Run OPA Tests**: Execute all Rego tests to verify they pass
   ```bash
   cd sbom_rego_rules && opa test .
   ```
   This:
   - Runs all `*_test.rego` files
   - Verifies rules work correctly with test data
   - Reports pass/fail status for each test
   - Should achieve 100% pass rate (currently 262/262 passing)

2. **Execution Verification** (Optional): Use execution-based verification to double-check
   ```bash
   python3 scripts/core/generate_sbom_validation_tests_execute.py --verify-only
   ```
   This executes rules with test data to ensure correctness (verification step, not generation).

3. **Fix Issues**: Address any validation failures
   - **TDD Principle**: If tests fail, fix the rules (tests are the contract)
   - Common issues: incorrect SBOM paths, missing imports, logic errors
   - Fix manually or with helper scripts

### Output
- Test results showing which tests pass/fail
- Fixed SBOM Rego rules in `sbom_rego_rules/`

## Phase 6: Training Data Generation

### Purpose
Convert validated SBOM Rego rules into training data for the Qwen3 model.

### Scripts Used
- **`generate_sbom_training_from_rules.py`** - Generate SBOM training data from validated Rego rules

### Process

1. **Generate SBOM Training Data**: Create training examples for SBOM rule generation
   ```bash
   cd rego-training/scripts/core
   python generate_sbom_training_from_rules.py
   ```
   This:
   - Reads all Rego files from `sbom_rego_rules/`
   - Extracts natural language from METADATA
   - Extracts Rego code
   - Validates against test cases
   - Creates training examples in Qwen3 chat format
   - Outputs to `sbom_data/qwen3-sbom-training-data.jsonl`

### Output
- `sbom_data/qwen3-sbom-training-data.jsonl` - SBOM rule generation training data

## Phase 7: Model Fine-tuning

### Purpose
Train Qwen3 model on the SBOM training data.

### Process

1. **Fine-tune Model**: Train on SBOM training data
   ```bash
   python finetune_qwen3.py \
     --training-data sbom_data/qwen3-sbom-training-data.jsonl \
     --model Qwen/Qwen3-1.7B \
     --output-dir ./qwen3-sbom-finetuned \
     --use-lora \
     --use-fp16 \
     --epochs 5 \
     --batch-size 4
   ```

### Output
- `qwen3-sbom-finetuned/` - Fine-tuned SBOM model directory

## Phase 8: Deployment

### Purpose
Deploy fine-tuned SBOM model for use.

### Process

Same as attestation training deployment process, but using the SBOM model:
- Direct inference with `inference_qwen3.py`
- Ollama deployment (merge LoRA, convert to GGUF, create Modelfile)

## Key Differences from Attestation Training

1. **Data Structure**: SBOMs are accessed directly from `input.attestations` using pure Rego (no library imports) by checking `predicateType`
2. **Directory Separation**: All SBOM files are in `sbom_data/` and `sbom_rego_rules/` directories
3. **System Prompt**: Training examples use SBOM-specific system prompts describing SBOM structure
4. **Test Data**: SBOM test cases use SBOM example data (e.g., from `sbom-example.json`)
5. **Execution-Based Test Generation**: Uses OPA to execute rules and verify test correctness (more accurate than pattern matching alone)

## Quick Reference: Common Workflows

### Starting SBOM Training from Scratch (TDD Workflow)

```bash
# 1. Extract requirements (if starting from comprehensive_test_cases.json)
python3 scripts/core/extract_sbom_requirements.py
# Or create sbom_data/requirements.json manually with natural_language, keys_used, type

# 2. Generate test definitions from requirements (TDD)
python3 scripts/core/generate_sbom_validation_tests_execute.py

# 3. Generate Rego test files
python3 scripts/core/generate_sbom_rego_tests.py

# 4. Generate Rego rules (to make tests pass)
# Option A: Use model to generate from requirements + tests
# Option B: Manually write rules
# Option C: Use existing rego_code from comprehensive_test_cases.json (legacy fallback)
python3 scripts/core/generate_sbom_rego_rules.py

# 5. Validate rules (TDD verification)
cd sbom_rego_rules && opa test .
# If tests fail, fix rules (tests are the contract!)

# 6. Generate training data
python3 scripts/core/generate_sbom_training_from_rules.py

# 7. Fine-tune model
python3 scripts/core/finetune_qwen3.py --training-data sbom_data/qwen3-sbom-training-data.jsonl --output-dir ./qwen3-sbom-finetuned
```

### Adding New SBOM Rules

```bash
# 1. Add to sbom_data/comprehensive_test_cases.json
# 2. Generate Rego rules
python3 scripts/core/generate_sbom_rego_rules.py

# 3. Generate validation tests
python3 scripts/core/generate_sbom_validation_tests_execute.py

# 4. Generate Rego test files
python3 scripts/core/generate_sbom_rego_tests.py

# 5. Validate
cd sbom_rego_rules && opa test .

# 6. Regenerate training data
python3 scripts/core/generate_sbom_training_from_rules.py

# 7. Retrain model
python3 scripts/core/finetune_qwen3.py --training-data sbom_data/qwen3-sbom-training-data.jsonl --output-dir ./qwen3-sbom-finetuned
```

## Current Statistics

- **Total Test Cases**: 202
- **Tests Passing**: 262/262 (100%)
- **Cases with Both Positive and Negative Tests**: 60/202 (29.7%)
- **Coverage**: 100% (all cases have at least one test)

## Best Practices

1. **Test Coverage**: Aim for 100% test coverage (currently 262/262 tests passing)
2. **Pure Rego**: Always use pure Rego, no library imports
3. **Direct Access**: Access SBOMs directly from `input.attestations`
4. **Format Support**: Handle both SPDX and CycloneDX formats
5. **Execution-Based Testing**: Use `generate_sbom_validation_tests_execute.py` for accurate test generation
6. **Validation**: Always run `opa test` to verify tests pass

## Reference Documentation

- **SBOM Structure**: See `docs/sbom-structure-training-data.md` for complete SBOM path mappings
- **Attestation Training**: See `docs/COMPLETE_PROCESS.md` for the attestation training process (for comparison)
- **General Training**: See `docs/COMPLETE_PROCESS.md` for general training workflow

## Example SBOM

An example SPDX SBOM is available at `rego-training/sbom-example.json`. This can be used as a reference for understanding SBOM structure and creating test cases.
