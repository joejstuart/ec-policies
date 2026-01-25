# Validation Test Generation

## Overview

The `test_case_definitions.json` file now contains **224 test cases** with validation test data, converted from `comprehensive_test_cases.json`.

## Purpose

This file is used by the validation system (`validate_and_add_training.py`) to:
1. **Test generated Rego code** - Verify that Rego code generated from natural language actually works
2. **Ensure correctness** - Each test case includes positive tests (should deny) and negative tests (should pass)
3. **Validate behavior** - Test that the Rego code produces the expected deny results

## Structure

Each test case in `test_case_definitions.json` has:

```json
{
  "test_cases": {
    "case_id": {
      "natural_language": "Description of what to check",
      "tests": [
        {
          "name": "should_deny_when_condition_violated",
          "input": {
            "attestations": [...]
          },
          "should_deny": true,
          "expected_msg_contains": "keyword"
        },
        {
          "name": "should_pass_when_condition_met",
          "input": {
            "attestations": [...]
          },
          "should_deny": false
        }
      ]
    }
  }
}
```

## Statistics

- **Total test cases:** 224
- **Total test scenarios:** 473
- **Average tests per case:** ~2.1

## Test Patterns

The validation tests cover various patterns:

1. **Parameter checks** - Verify task parameters have correct values
2. **Status checks** - Verify task status is correct
3. **Result checks** - Verify tasks produced expected results
4. **Bundle checks** - Verify task bundle references exist
5. **Compound checks** - Verify all tasks meet conditions
6. **Subject checks** - Verify subject images exist and are valid
7. **Materials checks** - Verify materials exist and are valid
8. **Metadata checks** - Verify metadata fields exist
9. **Step checks** - Verify task steps are valid
10. **Top-level checks** - Verify _type and predicateType

## Usage

The validation system uses these test cases to:

```python
# Load test case definitions
test_definitions = load_test_case_definitions()

# Find matching test case for natural language
test_case = find_matching_test_case(natural_language, test_definitions)

# Validate Rego code against test cases
result = validate_with_test_definitions(natural_language, rego_code, test_definitions)
```

## Generation

The validation tests were generated using `generate_validation_tests.py`, which:
1. Reads `comprehensive_test_cases.json`
2. Analyzes each test case's natural language and keys used
3. Generates appropriate test data (positive and negative scenarios)
4. Outputs in `test_case_definitions.json` format

## Next Steps

These validation test cases can now be used to:
1. Validate candidate Rego code before adding to training data
2. Ensure generated Rego code works correctly
3. Test the validation system itself
4. Generate more comprehensive test coverage
