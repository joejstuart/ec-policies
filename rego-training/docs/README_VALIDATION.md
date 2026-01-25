# Rego Training Data Validation System

This system validates candidate Rego code against natural language requirements before adding it to training data.

## Overview

The validation system ensures that:
1. Rego code is syntactically correct
2. Rego code produces expected results for positive test cases
3. Rego code produces no false positives for negative test cases
4. Only validated examples are added to training data

## Components

### 1. `validate_rego_training.py`
Core validation engine that:
- Extracts Rego code from markdown
- Runs OPA to evaluate Rego against test data
- Validates output matches expectations

### 2. `test_case_definitions.json`
Predefined test cases for common natural language patterns:
- Positive tests (should deny)
- Negative tests (should pass)
- Expected message validation

### 3. `validate_and_add_training.py`
Workflow script that:
- Validates candidate Rego code
- Adds to training data if validation passes
- Provides CLI interface

## Usage

### Validate a Single Example

```bash
# Validate Rego code against natural language requirement
python validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego

# Validate and add if passes
python validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego \
  --add-if-valid
```

### Validate Entire Training File

```bash
# Validate all examples in JSONL file
python validate_and_add_training.py --validate-file qwen3-training-data.jsonl
```

### Using the Core Validator Directly

```python
from validate_rego_training import validate_training_example

natural_language = "Verify the prefetch-dependencies task was not invoked with permissive mode"
assistant_content = """```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildDefinition.tasks
    task.name == "prefetch-dependencies"
    task.invocation.parameters.mode == "permissive"
    result := "prefetch-dependencies mode is permissive"
}
```"""

result = validate_training_example(natural_language, assistant_content)
if result.passed:
    print("✅ Validation passed!")
else:
    print("❌ Validation failed:")
    for error in result.errors:
        print(f"  - {error}")
```

## Test Case Definitions

Test cases are defined in `test_case_definitions.json`. Each test case includes:

- **natural_language**: The requirement in natural language
- **tests**: Array of test scenarios:
  - **name**: Test name
  - **input**: Input attestation data
  - **should_deny**: Boolean - should the rule deny?
  - **expected_msg_contains**: Optional - expected message substring

### Example Test Case

```json
{
  "natural_language": "Verify the prefetch-dependencies task was not invoked with permissive mode",
  "tests": [
    {
      "name": "should_deny_when_permissive",
      "input": {
        "attestations": [{
          "statement": {
            "predicate": {
              "buildConfig": {
                "tasks": [{
                  "name": "prefetch-dependencies",
                  "invocation": {
                    "parameters": {"mode": "permissive"}
                  }
                }]
              }
            }
          }
        }]
      },
      "should_deny": true,
      "expected_msg_contains": "permissive"
    }
  ]
}
```

## Adding New Test Cases

1. Add test case definition to `test_case_definitions.json`
2. Include both positive (should deny) and negative (should pass) tests
3. Use realistic attestation structures
4. Test edge cases (missing fields, different values, etc.)

## Workflow

### Recommended Workflow

1. **Generate Candidate Rego**: Use LLM to generate Rego from natural language
2. **Validate**: Run validation script
3. **Review Errors**: Fix any issues found
4. **Re-validate**: Run again until passes
5. **Add to Training**: Use `--add-if-valid` flag

### Example Workflow

```bash
# Step 1: Generate candidate (using LLM or manually)
cat > candidate.rego << 'EOF'
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "prefetch-dependencies"
    task.invocation.parameters.mode == "permissive"
    result := "prefetch-dependencies mode is permissive"
}
EOF

# Step 2: Validate
python validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego

# Step 3: If passes, add to training data
python validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego \
  --add-if-valid
```

## Requirements

- Python 3.7+
- OPA (Open Policy Agent) installed and in PATH
- Access to policy directory for imports

## Troubleshooting

### OPA Not Found
```bash
# Install OPA
brew install opa  # macOS
# or download from https://www.openpolicyagent.org/docs/latest/
```

### Import Errors
The validator creates a temporary package. If your Rego code uses imports from the policy directory, ensure the policy directory is accessible.

### Test Cases Not Matching
If validation fails because test cases don't match:
1. Check `test_case_definitions.json` for matching natural language
2. Add new test case definition if needed
3. Ensure test input data matches your Rego code's expected structure

## Future Improvements

- [ ] Automatic test case generation from natural language
- [ ] Support for multiple SLSA versions (v0.2, v1.0)
- [ ] Integration with LLM for candidate generation
- [ ] Batch validation and filtering
- [ ] Test coverage reporting
