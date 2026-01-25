# Training Data Generation Plan

This document outlines a comprehensive plan for generating, validating, and managing training data for Qwen3 model fine-tuning.

## Overview

The goal is to create high-quality training examples that:
1. Map natural language policy requirements to correct Rego code
2. Use proper JSON paths from the attestation structure
3. Are validated before being added to the training dataset
4. Cover diverse patterns and edge cases

## Training Data Requirements

### Format Requirements

Each training example must be in JSONL format with this structure:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "<system prompt with attestation structure context>"
    },
    {
      "role": "user",
      "content": "<natural language policy requirement>"
    },
    {
      "role": "assistant",
      "content": "<Rego code in markdown + explanation>"
    }
  ]
}
```

### Content Requirements

1. **System Prompt**: Must include:
   - Reference to attestation structure documentation
   - Key path mappings
   - Common patterns
   - SLSA version differences

2. **Natural Language**: Should be:
   - Clear and specific
   - Actionable (describes what to check)
   - Uses standard terminology

3. **Rego Code**: Must:
   - Be syntactically correct
   - Use correct JSON paths
   - Follow Rego best practices
   - Include proper error messages

4. **Explanation**: Should:
   - Break down the rule step-by-step
   - Explain the logic
   - Reference the paths used

## Using Attestation Structure Documentation

### Reference Document

The `attestation-structure-training-data.md` file contains:
- Complete JSON path mappings
- Natural language to path translations
- Common patterns
- Example mappings

### Integration Strategy

#### 1. System Prompt Generation

Extract key sections from the documentation to include in system prompts:

```python
def generate_system_prompt():
    """Generate system prompt from attestation structure documentation."""
    # Read the documentation
    with open("docs/attestation-structure-training-data.md") as f:
        doc_content = f.read()
    
    # Extract key sections:
    # - Top-Level Navigation table
    # - Task Structure table
    # - Common Patterns section
    
    system_prompt = f"""You are an expert at writing Rego policy rules for Enterprise Contract.

{extract_section(doc_content, "## Key Path Mappings")}
{extract_section(doc_content, "## Common Patterns")}

Write Rego deny rules that check the attestation structure."""
    return system_prompt
```

#### 2. Path Validation

Use the documentation to validate that generated Rego uses correct paths:

```python
def validate_paths_used(rego_code, natural_language):
    """Validate that Rego code uses paths from the documentation."""
    # Extract paths from documentation
    documented_paths = extract_paths_from_docs()
    
    # Extract paths used in Rego code
    used_paths = extract_paths_from_rego(rego_code)
    
    # Check if all used paths are documented
    for path in used_paths:
        if path not in documented_paths:
            return False, f"Path {path} not found in documentation"
    
    return True, "All paths validated"
```

#### 3. Pattern Matching

Match natural language to documented patterns:

```python
def find_matching_pattern(natural_language):
    """Find matching pattern from documentation."""
    # Look for keywords in natural language
    if "task" in natural_language and "parameter" in natural_language:
        return "task_parameter_check"
    elif "task" in natural_language and "status" in natural_language:
        return "task_status_check"
    # ... more patterns
```

## Validation Strategy

### Multi-Layer Validation

#### Layer 1: Syntax Validation
- Rego code compiles
- No syntax errors
- Proper package declaration

#### Layer 2: Path Validation
- All paths exist in documentation
- Paths match natural language description
- Correct SLSA version paths used

#### Layer 3: Functional Validation
- Test cases pass (positive and negative)
- Expected deny results match
- No false positives/negatives

#### Layer 4: Quality Validation
- Code follows best practices
- Error messages are clear
- Explanation is accurate

### Validation Workflow

```
1. Generate Candidate
   ↓
2. Syntax Check (OPA parse)
   ↓
3. Path Validation (against docs)
   ↓
4. Generate Test Cases
   ↓
5. Run Functional Tests
   ↓
6. Quality Review
   ↓
7. Add to Training Data (if all pass)
```

## Generation Process

### Step 1: Define Requirements

Create a list of natural language requirements covering:

- **Task Parameter Checks**: Verify specific parameter values
- **Task Status Checks**: Verify task completion
- **Task Bundle Checks**: Verify trusted bundles
- **Task Result Checks**: Verify results exist/have values
- **Task Annotation Checks**: Verify annotations
- **Task Label Checks**: Verify labels
- **Build Metadata Checks**: Verify timestamps, etc.
- **Multiple Conditions**: Complex rules with AND/OR logic

### Step 2: Generate Candidates

For each requirement:

1. **Use LLM with Context**:
   ```python
   prompt = f"""
   {system_prompt_from_docs}
   
   User requirement: {natural_language}
   
   Generate Rego code that:
   - Uses paths from the attestation structure documentation
   - Follows the common patterns
   - Includes proper error messages
   """
   ```

2. **Manual Generation**: For complex cases, manually write Rego

3. **Template-Based**: Use templates for common patterns

### Step 3: Validate Candidates

Run through validation pipeline:

```bash
python3 validate_and_add_training.py \
  --validate "<natural_language>" candidate.rego
```

### Step 4: Generate Test Cases

For each validated example:

1. **Extract from test_case_definitions.json** if exists
2. **Generate automatically** based on pattern
3. **Create manually** for complex cases

### Step 5: Final Validation

Run complete validation suite:

```bash
# Validate syntax
opa test candidate.rego

# Validate paths
python3 validate_paths.py candidate.rego

# Validate functionality
python3 validate_and_add_training.py --validate ... candidate.rego
```

### Step 6: Add to Training Data

If all validations pass:

```bash
python3 validate_and_add_training.py \
  --validate "<natural_language>" candidate.rego \
  --add-if-valid
```

## Automation Script

### `generate_training_data.py`

A script that automates the generation process:

```python
#!/usr/bin/env python3
"""
Automated training data generation with validation.
"""

import json
from pathlib import Path
from validate_rego_training import validate_training_example
from validate_and_add_training import add_to_training_data

def generate_training_example(natural_language, llm_client=None):
    """Generate and validate a training example."""
    
    # Step 1: Generate system prompt from docs
    system_prompt = generate_system_prompt_from_docs()
    
    # Step 2: Generate Rego code
    if llm_client:
        rego_code = llm_client.generate(system_prompt, natural_language)
    else:
        rego_code = generate_manually(natural_language)
    
    # Step 3: Format as assistant response
    assistant_content = format_rego_response(rego_code)
    
    # Step 4: Validate
    result = validate_training_example(natural_language, assistant_content)
    
    if result.passed:
        # Step 5: Add to training data
        add_to_training_data(natural_language, assistant_content)
        return True, "Added to training data"
    else:
        return False, result.errors

def generate_system_prompt_from_docs():
    """Extract system prompt from documentation."""
    doc_path = Path("docs/attestation-structure-training-data.md")
    # Extract relevant sections
    # Format as system prompt
    pass

def format_rego_response(rego_code):
    """Format Rego code as assistant response."""
    return f"""```rego
{rego_code}
```

This rule validates the requirement by:
1. [Step-by-step explanation]
"""
```

## Quality Criteria

### Must Have

- ✅ Syntactically correct Rego
- ✅ All paths validated against documentation
- ✅ Test cases pass (positive and negative)
- ✅ Proper error messages
- ✅ Clear explanation

### Should Have

- ✅ Covers diverse patterns
- ✅ Includes edge cases
- ✅ Follows Rego best practices
- ✅ Uses appropriate SLSA version paths

### Nice to Have

- ✅ Complex multi-condition rules
- ✅ Uses helper functions from lib.tekton
- ✅ Handles both SLSA v0.2 and v1.0

## Coverage Goals

### Pattern Coverage

- [ ] Task parameter checks (10+ examples)
- [ ] Task status checks (5+ examples)
- [ ] Task bundle checks (5+ examples)
- [ ] Task result checks (10+ examples)
- [ ] Task annotation checks (5+ examples)
- [ ] Task label checks (5+ examples)
- [ ] Build metadata checks (5+ examples)
- [ ] Multiple conditions (5+ examples)
- [ ] Edge cases (10+ examples)

### Total Target

- **Minimum**: 50 validated examples
- **Target**: 100 validated examples
- **Ideal**: 200+ validated examples

## Workflow Diagram

```
┌─────────────────────────────────────┐
│  Natural Language Requirement       │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Generate System Prompt from Docs   │
│  (attestation-structure-training-  │
│   data.md)                          │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Generate Rego Code                 │
│  (LLM or Manual)                    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Layer 1: Syntax Validation         │
│  (OPA parse)                         │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Layer 2: Path Validation           │
│  (Check against docs)               │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Layer 3: Generate Test Cases        │
│  (From test_case_definitions.json)  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Layer 4: Functional Validation     │
│  (Run test cases with OPA)           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Layer 5: Quality Review            │
│  (Best practices, explanations)     │
└──────────────┬──────────────────────┘
               │
               ▼
         ┌─────┴─────┐
         │           │
      Pass?        Fail?
         │           │
         ▼           ▼
    Add to      Fix Issues
    Training    & Retry
    Data
```

## Implementation Steps

### Phase 1: Foundation (Week 1)

1. ✅ Create validation system
2. ✅ Create documentation structure
3. ⏳ Create generation script skeleton
4. ⏳ Create test case library

### Phase 2: Core Generation (Week 2)

1. ⏳ Implement system prompt generation from docs
2. ⏳ Implement path validation
3. ⏳ Create LLM integration (optional)
4. ⏳ Generate first 20 examples

### Phase 3: Expansion (Week 3-4)

1. ⏳ Expand test case library
2. ⏳ Generate 50+ examples
3. ⏳ Validate all examples
4. ⏳ Review and refine

### Phase 4: Automation (Week 5)

1. ⏳ Full automation script
2. ⏳ Batch processing
3. ⏳ Quality metrics
4. ⏳ Documentation

## Tools and Scripts Needed

### Existing

- ✅ `validate_rego_training.py` - Core validator
- ✅ `validate_and_add_training.py` - Workflow script
- ✅ `test_case_definitions.json` - Test case library

### To Create

- ⏳ `generate_training_data.py` - Main generation script
- ⏳ `extract_docs_content.py` - Extract sections from docs
- ⏳ `validate_paths.py` - Path validation against docs
- ⏳ `generate_test_cases.py` - Auto-generate test cases
- ⏳ `batch_validate.py` - Batch validation tool

## Success Metrics

### Quality Metrics

- **Validation Pass Rate**: > 90%
- **Path Accuracy**: 100% (all paths from docs)
- **Test Coverage**: > 80% of examples have test cases
- **Syntax Errors**: 0%

### Quantity Metrics

- **Total Examples**: 100+
- **Pattern Coverage**: All major patterns covered
- **Edge Cases**: 10+ edge case examples

### Time Metrics

- **Generation Time**: < 5 min per example (with validation)
- **Validation Time**: < 1 min per example
- **Total Time**: < 10 hours for 100 examples

## Next Steps

1. **Create Generation Script**: Implement `generate_training_data.py`
2. **Extract Doc Content**: Create utility to extract sections from docs
3. **Path Validator**: Create path validation against documentation
4. **Test Case Generator**: Auto-generate test cases from patterns
5. **Generate First Batch**: Create 20 validated examples
6. **Review and Iterate**: Refine based on results

## References

- [Attestation Structure Documentation](attestation-structure-training-data.md)
- [Validation System Guide](README_VALIDATION.md)
- [Training Data Summary](../TRAINING_DATA_SUMMARY.md)
