# SBOM Test-Driven Development Workflow

## Overview

This document describes the **Test-Driven Development (TDD)** approach for SBOM policy generation, where tests define the contract and rules implement it.

## Workflow

```
Requirements (natural_language, keys_used)
    ↓
Test Definitions (test_case_definitions.json)
    ↓
Rego Test Files (*_test.rego)
    ↓
Rego Rules (*.rego) - Generated to make tests pass
```

## Benefits

1. **Tests are the source of truth** - They define what the rule should do
2. **No circular dependency** - Tests don't depend on rules
3. **Clear contract** - Tests specify expected behavior
4. **TDD approach** - Write tests first, then implementation
5. **Separation of concerns** - Requirements, tests, and implementation are separate

## Phase 1: Requirements Definition

### File: `sbom_data/requirements.json`

Contains only requirements (no implementation):

```json
{
  "requirements": {
    "sbom_spdx_001": {
      "natural_language": "Verify the SPDX SBOM contains packages.",
      "keys_used": [
        "input.attestations",
        "statement.predicateType",
        "statement.predicate.packages"
      ],
      "type": "single_key"
    }
  }
}
```

**Fields:**
- `natural_language` - What to check
- `keys_used` - Which fields are accessed
- `type` - single_key or compound

**No `rego_code` field** - Implementation comes later!

## Phase 2: Generate Test Definitions

### Script: `generate_sbom_test_definitions.py`

Generates test data from requirements:

```bash
python3 scripts/core/generate_sbom_test_definitions.py
```

**Input:** `sbom_data/requirements.json`
**Output:** `sbom_data/test_case_definitions.json`

**Process:**
1. Reads requirements (natural_language, keys_used)
2. Generates test data variations based on requirements
3. Creates positive tests (should_deny: true) and negative tests (should_deny: false)
4. Uses execution-based approach to verify test data is correct

**Output Structure:**
```json
{
  "test_cases": {
    "sbom_spdx_001": {
      "natural_language": "Verify the SPDX SBOM contains packages.",
      "keys_used": [...],
      "tests": [
        {
          "name": "should_deny_when_no_packages",
          "input": {...},
          "should_deny": true
        },
        {
          "name": "should_pass_when_has_packages",
          "input": {...},
          "should_deny": false
        }
      ]
    }
  }
}
```

## Phase 3: Generate Rego Test Files

### Script: `generate_sbom_rego_tests.py`

Generates OPA test files from test definitions:

```bash
python3 scripts/core/generate_sbom_rego_tests.py
```

**Input:** `sbom_data/test_case_definitions.json`
**Output:** `sbom_rego_rules/*_test.rego`

**Process:**
1. Reads test definitions
2. Generates `_test.rego` files with `with input as {...}` blocks
3. Tests reference a package name (e.g., `data.sbom_spdx_001.deny`)

**Example Output:**
```rego
package sbom_spdx_001_test

import rego.v1
import data.sbom_spdx_001

test_deny_when_no_packages if {
    count(sbom_spdx_001.deny) > 0
    with input as {
        "attestations": [...]
    }
}

test_pass_when_has_packages if {
    count(sbom_spdx_001.deny) == 0
    with input as {
        "attestations": [...]
    }
}
```

## Phase 4: Generate Rego Rules

### Current Implementation

The existing `generate_sbom_rego_rules.py` script supports both TDD and legacy workflows:

```bash
python3 scripts/core/generate_sbom_rego_rules.py
```

**TDD Workflow:**
- Reads from `sbom_data/requirements.json` + `sbom_data/test_case_definitions.json`
- Currently falls back to `comprehensive_test_cases.json` if `rego_code` exists there (legacy support)
- For pure TDD: Rules should be generated to make tests pass

**Legacy Workflow:**
- Reads from `sbom_data/comprehensive_test_cases.json`
- Extracts existing `rego_code` directly

**Output:** `sbom_rego_rules/*.rego`

### Future: Model-Generated Rules (Optional)

For true TDD with model generation, you could create a script that:

1. Reads `sbom_data/requirements.json` (natural language)
2. Reads `sbom_data/test_case_definitions.json` (test examples)
3. For each requirement, creates a prompt with:
   - Natural language description
   - Keys used
   - Example test cases (what should deny/pass)
4. Uses a fine-tuned model to generate Rego code
5. Writes `.rego` file

This would be a new script: `generate_sbom_rego_rules_from_model.py` (not yet implemented)

### Option: Manual Rules

Manually write rules to make tests pass (traditional TDD). Edit `sbom_rego_rules/*.rego` files directly.

## Phase 5: Validate

Run tests to verify rules are correct:

```bash
cd sbom_rego_rules && opa test .
```

All tests should pass. If not, fix the rules (not the tests - tests are the contract!).

## Migration Plan

### Step 1: Extract Requirements

Create `sbom_data/requirements.json` from `comprehensive_test_cases.json`:

```python
# Remove rego_code field, keep only requirements
requirements = {
    case_id: {
        "natural_language": case["natural_language"],
        "keys_used": case["keys_used"],
        "type": case["type"]
    }
    for case_id, case in comprehensive_test_cases.items()
}
```

### Step 2: Update Test Generation

Modify `generate_sbom_validation_tests_execute.py` to:
- Read from `requirements.json` instead of `comprehensive_test_cases.json`
- Generate test data from requirements only (no rego_code needed)
- Output to `test_case_definitions.json`

### Step 3: Update Rule Generation

The existing `generate_sbom_rego_rules.py` already supports TDD workflow:
- Reads from `requirements.json` (TDD) or `comprehensive_test_cases.json` (legacy)
- Currently uses legacy fallback for `rego_code`
- For pure TDD: Rules should be generated from requirements + tests (model or manual)
- Rules must make tests pass (TDD principle)

### Step 4: Remove rego_code from comprehensive_test_cases.json

Once migration is complete, `comprehensive_test_cases.json` can be deprecated or removed.

## Benefits of This Approach

1. **Tests define contract** - Clear specification of expected behavior
2. **No redundancy** - Rego code only exists in `.rego` files
3. **TDD workflow** - Write tests first, then implementation
4. **Model training** - Can train model on requirements → rules (with tests as validation)
5. **Easier maintenance** - Change requirements, regenerate tests, update rules

## Example Workflow

```bash
# 1. Define requirements
# Edit sbom_data/requirements.json

# 2. Generate test definitions
python3 scripts/core/generate_sbom_test_definitions.py

# 3. Generate Rego test files
python3 scripts/core/generate_sbom_rego_tests.py

# 4. Generate Rego rules (uses legacy fallback for now, or manual)
python3 scripts/core/generate_sbom_rego_rules.py
# Note: Currently uses comprehensive_test_cases.json as fallback for rego_code
# For pure TDD, rules should be generated from requirements + tests (model or manual)

# 5. Validate
cd sbom_rego_rules && opa test .

# 6. If tests fail, fix rules (not tests!)
# Edit sbom_rego_rules/*.rego
# Run: opa test . again
```

## Key Principle

**Tests are the source of truth. Rules implement the tests.**

If a test fails, the rule is wrong (not the test). Tests define what the rule should do.
