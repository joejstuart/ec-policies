# Rego Training Data Validation System - Summary

## Problem

The original training data contained Rego code that was incorrect or didn't match the natural language requirements. We needed a system to validate candidate Rego code before adding it to training data.

## Solution

A comprehensive validation system that:
1. **Generates test cases** from natural language requirements
2. **Runs Rego code** against test data using OPA
3. **Validates output** matches expectations
4. **Only adds to training data** if all tests pass

## Files Created

### Core Validation Engine

1. **`validate_rego_training.py`** (Main validator)
   - Extracts Rego code from markdown
   - Runs OPA to evaluate Rego against test data
   - Validates output matches expectations
   - Supports both programmatic and CLI usage

2. **`test_case_definitions.json`** (Test case library)
   - Predefined test cases for common patterns
   - Positive tests (should deny)
   - Negative tests (should pass)
   - Expected message validation

3. **`validate_and_add_training.py`** (Workflow script)
   - CLI interface for validation
   - Validates single examples or entire files
   - Optionally adds to training data if validation passes

4. **`README_VALIDATION.md`** (Documentation)
   - Complete usage guide
   - Examples and workflows
   - Troubleshooting

5. **`example_validation_workflow.sh`** (Example script)
   - Demonstrates usage patterns

## How It Works

### 1. Test Case Generation

For each natural language requirement, the system:
- Identifies the pattern (e.g., "parameter check", "status check")
- Generates positive test cases (should deny)
- Generates negative test cases (should pass)
- Creates realistic attestation input data

### 2. Rego Code Validation

The validator:
- Extracts Rego code from markdown blocks
- Creates a temporary Rego package
- Runs OPA with test input data
- Checks if deny results match expectations

### 3. Validation Results

Returns:
- ✅ Pass/fail status
- List of errors (if any)
- Detailed test results

## Usage Examples

### Validate a Single Example

```bash
python3 validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego
```

### Validate and Add if Passes

```bash
python3 validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego \
  --add-if-valid
```

### Validate Entire Training File

```bash
python3 validate_and_add_training.py \
  --validate-file qwen3-training-data.jsonl
```

### Programmatic Usage

```python
from validate_rego_training import validate_training_example

result = validate_training_example(
    natural_language="Verify the prefetch-dependencies task was not invoked with permissive mode",
    assistant_content="```rego\n...\n```"
)

if result.passed:
    # Add to training data
    pass
```

## Test Case Structure

Each test case includes:
- **name**: Descriptive test name
- **input**: Attestation data structure
- **should_deny**: Boolean - should rule deny?
- **expected_msg_contains**: Optional expected message substring

## Current Test Cases

The system includes test cases for:
1. ✅ Prefetch-dependencies permissive mode check
2. ✅ All tasks completed successfully
3. ✅ Build task IMAGE_URL result check

## Adding New Test Cases

1. Add to `test_case_definitions.json`:
   ```json
   {
     "natural_language": "Your requirement here",
     "tests": [
       {
         "name": "should_deny_when_condition",
         "input": { /* attestation data */ },
         "should_deny": true
       },
       {
         "name": "should_pass_when_condition",
         "input": { /* attestation data */ },
         "should_deny": false
       }
     ]
   }
   ```

2. Test cases should cover:
   - Positive cases (should deny)
   - Negative cases (should pass)
   - Edge cases (missing fields, different values)

## Requirements

- Python 3.7+
- OPA (Open Policy Agent) installed
- Access to policy directory (for imports if needed)

## Workflow Integration

### Recommended Workflow

1. **Generate Candidate**: Use LLM or manual creation
2. **Validate**: Run validation script
3. **Fix Issues**: Address any validation errors
4. **Re-validate**: Run again until passes
5. **Add to Training**: Use `--add-if-valid` flag

### Automated Workflow (Future)

```python
# Generate candidate
candidate = llm.generate_rego(natural_language)

# Validate
result = validate_training_example(natural_language, candidate)

# Add if valid
if result.passed:
    add_to_training_data(natural_language, candidate)
else:
    # Provide feedback to LLM for regeneration
    feedback = generate_feedback(result.errors)
    candidate = llm.regenerate(candidate, feedback)
```

## Benefits

1. **Quality Assurance**: Only correct Rego code enters training data
2. **Automated Testing**: No manual verification needed
3. **Consistency**: All examples follow same validation process
4. **Scalability**: Easy to add new test cases
5. **Confidence**: Training data is verified correct

## Next Steps

1. ✅ **System Created**: Core validation system in place
2. ⏳ **Expand Test Cases**: Add more test case definitions
3. ⏳ **Automate Generation**: Integrate with LLM for candidate generation
4. ⏳ **Batch Processing**: Validate and filter entire datasets
5. ⏳ **Coverage Reporting**: Track which patterns are covered

## Notes

- The system uses OPA for Rego evaluation, ensuring compatibility with actual policy execution
- Test cases use realistic attestation structures matching the codebase
- The validator handles both `buildConfig.tasks` and `buildDefinition.tasks` paths
- All scripts are executable and ready to use
