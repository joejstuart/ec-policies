# Test Creation Training Data

This document describes the additional training data generated for teaching the model how to create tests for Rego rules.

## Overview

The training data includes two types of examples:

1. **Rule-to-Test**: Given a Rego rule, create tests for it
2. **Requirement-to-Rule-and-Test**: Given a requirement, create both the rule and tests

## Files

### `data/qwen3-test-creation-training.jsonl`
- **Format**: JSONL (JSON Lines)
- **Examples**: 432 training examples
  - 216 Rule-to-Test examples
  - 216 Requirement-to-Rule-and-Test examples
- **Purpose**: Teach the model how to write tests and create complete rule+test solutions

### `data/qwen3-complete-training.jsonl`
- **Format**: JSONL (JSON Lines)
- **Examples**: 651 total (219 rule generation + 432 test creation)
- **Purpose**: Combined training dataset with all examples shuffled

## Training Example Types

### Type 1: Rule-to-Test

**User Prompt Pattern:**
```
Given the following Rego policy rule, create a complete test file for it.

**Requirement**: {natural_language}

**Rego Rule**:
```rego
package {package_name}

{rego_code}
```

Create a `{package_name}_test.rego` file with comprehensive test cases.
```

**Assistant Response:**
- Complete test file with package, imports, and test rules
- Both positive (should deny) and negative (should pass) test cases
- Realistic attestation data
- Explanation of test coverage

### Type 2: Requirement-to-Rule-and-Test

**User Prompt Pattern:**
```
I need a Rego policy rule to validate the following requirement, along with a complete test file for it.

**Requirement**: {natural_language}

Create:
1. A Rego rule file (`{package_name}.rego`) that implements the validation
2. A corresponding test file (`{package_name}_test.rego`) with comprehensive test cases
```

**Assistant Response:**
- Complete Rego rule with package and deny logic
- Complete test file with comprehensive test cases
- Explanation of both the rule and tests

## Usage

### Generate Test Creation Training Data

```bash
python generate_test_creation_training.py
```

This creates `data/qwen3-test-creation-training.jsonl` with 432 examples.

### Merge with Base Training Data

```bash
python merge_training_data.py
```

This creates `data/qwen3-complete-training.jsonl` with all 651 examples shuffled.

### Use for Fine-tuning

You can use either:
- **Separate files**: Fine-tune on rule generation first, then test creation
- **Merged file**: Fine-tune on the complete dataset for a model that can do both

```bash
# Use merged file for comprehensive training
python finetune_qwen3.py --training-data data/qwen3-complete-training.jsonl

# Or use separate files for focused training
python finetune_qwen3.py --training-data data/qwen3-training-data.jsonl
```

## Benefits

1. **Test Writing Skills**: Model learns to write comprehensive tests for any Rego rule
2. **Complete Solutions**: Model learns to create both rules and tests from requirements
3. **Best Practices**: Model learns OPA testing conventions and patterns
4. **Real-world Workflow**: Matches actual development workflow (rule → test or requirement → rule+test)

## Training Data Statistics

- **Rule Generation**: 219 examples (requirement → rule)
- **Rule-to-Test**: 216 examples (rule → tests)
- **Requirement-to-Rule-and-Test**: 216 examples (requirement → rule + tests)
- **Total**: 651 examples

## Example Use Cases

After fine-tuning, the model can:

1. **Generate tests for existing rules**:
   ```
   User: Given this Rego rule [rule code], create tests for it
   Model: [Generates complete test file]
   ```

2. **Create complete solutions**:
   ```
   User: I need a rule to verify all tasks have status "Succeeded" with tests
   Model: [Generates both rule.rego and rule_test.rego]
   ```

3. **Understand test patterns**:
   - When to use `count(deny) > 0` vs `count(deny) == 0`
   - How to structure test data
   - How to quote object keys properly
   - How to create comprehensive test coverage
