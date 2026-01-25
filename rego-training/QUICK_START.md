# Quick Start Guide - Training Data Generation

## Overview

This guide provides a quick reference for generating validated training data.

## The Process

```
Natural Language → Generate Rego → Validate → Add to Training Data
```

## Step-by-Step

### 1. Define Your Requirement

Write a clear natural language requirement:

```
"Verify the prefetch-dependencies task was not invoked with permissive mode"
```

### 2. Generate Rego Code

Either:
- **Manual**: Write Rego code yourself
- **LLM**: Use an LLM with the attestation structure docs as context
- **Template**: Use a template for common patterns

### 3. Validate

```bash
cd rego-training
python3 generate_training_data.py \
  --natural-language "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  --rego-file candidate.rego
```

This will:
- ✅ Check syntax
- ✅ Validate paths against documentation
- ✅ Run functional tests
- ✅ Report any issues

### 4. Add to Training Data

If validation passes:

```bash
python3 generate_training_data.py \
  --natural-language "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  --rego-file candidate.rego \
  --add
```

## Using the Documentation

The `docs/attestation-structure-training-data.md` file is your reference for:

- **JSON Paths**: What paths to use in Rego code
- **Natural Language Mappings**: How to describe paths
- **Common Patterns**: Reusable code patterns
- **Examples**: Working examples

### Example: Finding the Right Path

1. Look in the documentation for your requirement type
2. Find the matching natural language description
3. Use the corresponding JSON path in your Rego code

**Example:**
- Requirement: "Check task parameters"
- Documentation says: `"task parameters"` → `task.invocation.parameters`
- Use in Rego: `task.invocation.parameters.mode`

## Validation Layers

Your Rego code must pass:

1. **Syntax Check**: Code compiles
2. **Path Validation**: All paths exist in documentation
3. **Functional Tests**: Test cases pass
4. **Quality Check**: Follows best practices

## Common Patterns

### Check Task Parameter

```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "<task-name>"
    task.invocation.parameters.<param> == "<value>"
    result := "<error message>"
}
```

### Check Task Status

```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.status != "Succeeded"
    result := sprintf("Task %s did not succeed", [task.name])
}
```

### Check Task Result

```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.name == "<task-name>"
    not "<result-name>" in {r.name | some r in task.results}
    result := "<error message>"
}
```

## Troubleshooting

### Validation Fails: Path Not Found

**Problem**: Path not in documentation

**Solution**: 
1. Check `docs/attestation-structure-training-data.md`
2. Use documented paths only
3. Verify SLSA version (v0.2 vs v1.0)

### Validation Fails: Test Cases Don't Pass

**Problem**: Rego code doesn't produce expected results

**Solution**:
1. Check test cases in `test_case_definitions.json`
2. Verify your logic matches the requirement
3. Test manually with OPA

### Validation Fails: Syntax Error

**Problem**: Rego code doesn't compile

**Solution**:
1. Run `opa test` to see syntax errors
2. Check Rego syntax reference
3. Verify package declaration

## Next Steps

- Read [Training Data Generation Plan](docs/TRAINING_DATA_GENERATION_PLAN.md) for detailed workflow
- Review [Attestation Structure Documentation](docs/attestation-structure-training-data.md) for path reference
- Check [Validation System Guide](docs/README_VALIDATION.md) for validation details
