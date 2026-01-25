# Rego Rules Directory

This directory contains candidate Rego rules generated from test case definitions. These rules can be validated against the test cases in `test_case_definitions.json` before being added to training data.

## Overview

- **Total Rules:** 224
- **Source:** Generated from `test_case_definitions.json` and `comprehensive_test_cases.json`
- **Purpose:** Candidate rules for validation and potential inclusion in training data

## File Naming

Each file is named based on the test case ID:
- `top_level_001.rego` - Top-level attestation field checks
- `subject_003.rego` - Subject image validation
- `metadata_008.rego` - Metadata field checks
- `materials_016.rego` - Materials validation
- `task_*.rego` - Task-related validations
- `step_*.rego` - Step-related validations
- `compound_*.rego` - Compound validations (multiple conditions)
- `single_key_*.rego` - Single key validations

## Rule Structure

Each Rego file follows this structure:

```rego
#
# METADATA
# title: Natural language description
# description: >-
#   Natural language description
# custom:
#   short_name: test_case_id
#   failure_msg: Policy validation failed
#
package <sanitized_case_id>

import rego.v1

deny contains result if {
    some attestation in input.attestations
    ...
    result := "..."
}
```

## Validation

These rules can be validated using the test cases in `../test_case_definitions.json`:

```bash
# Validate a single rule
python ../validate_and_add_training.py --validate "natural language" rego_rules/case_id.rego

# Validate all rules
for file in rego_rules/*.rego; do
    # Extract natural language and validate
    ...
done
```

## Categories

### Top-Level Fields (2 rules)
- `_type` validation
- `predicateType` validation

### Subject Fields (5 rules)
- Subject existence
- Subject name validation
- Subject digest validation
- Subject SHA256 validation

### Materials Fields (7 rules)
- Materials existence
- Material URI validation
- Material digest validation
- Material SHA256/SHA1 validation
- Git URI validation for SHA1 materials

### Metadata Fields (8 rules)
- Build timestamps
- Completeness fields
- Reproducibility

### Task Fields (150+ rules)
- Task status
- Task parameters
- Task results
- Task bundle references
- Task annotations/labels
- Task timestamps
- Task steps
- Task configSource

### Step Fields (7 rules)
- Step entryPoint
- Step arguments
- Step annotations
- Step environment (image, container)

### SLSA v1.0 Fields (8 rules)
- BuildDefinition fields
- ExternalParameters
- InternalParameters
- RunDetails

### Compound Rules (120+ rules)
- Multiple condition checks
- Cross-field validation
- Format validation
- Uniqueness checks

## Usage

1. **Review** - Review each rule to ensure it matches the natural language requirement
2. **Validate** - Run validation tests to ensure the rule works correctly
3. **Test** - Test against real attestation data
4. **Add to Training** - If validated, add to training data for Qwen3 model

## Next Steps

1. Validate all rules against test cases
2. Fix any issues found during validation
3. Generate training data from validated rules
4. Train Qwen3 model with the validated rules
