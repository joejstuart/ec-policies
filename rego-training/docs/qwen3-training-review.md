# Qwen3 Training Data Review

## Overview

This document reviews the training data prepared for training a Qwen3 model to generate Rego policy rules from natural language descriptions.

## Training Data Files

### 1. `qwen3-training-data.jsonl`
**Format**: JSONL (JSON Lines) - one training example per line  
**Structure**: Chat format with system/user/assistant messages  
**Examples**: 9 diverse examples covering common patterns

### 2. `attestation-training-examples.json`
**Format**: Structured JSON with detailed metadata  
**Purpose**: Reference documentation and detailed examples  
**Use**: Can be used to generate additional training examples programmatically

### 3. `attestation-structure-training-data.md`
**Format**: Markdown documentation  
**Purpose**: Human-readable reference for attestation structure  
**Use**: Documentation and context for understanding the data structure

## Training Data Quality Assessment

### ✅ Strengths

1. **Proper Format**: JSONL format is correct for Qwen3 training
2. **Chat Format**: Uses system/user/assistant message structure that Qwen3 expects
3. **System Context**: Each example includes comprehensive system prompt with:
   - Attestation structure explanation
   - Task structure details
   - Common patterns
   - Path variations (SLSA v0.2, v1.0, alternative formats)

4. **Diverse Examples**: Covers multiple scenarios:
   - Parameter checking (mode, sslVerify)
   - Status checking
   - Bundle reference validation
   - Result validation
   - Annotation checking
   - Timestamp validation

5. **Clear Explanations**: Each assistant response includes:
   - Complete Rego code
   - Step-by-step explanation
   - Code comments explaining the logic

### ⚠️ Areas for Improvement

1. **Example Count**: Currently 9 examples - consider adding more for better generalization:
   - More parameter checking examples
   - More result checking examples
   - Label checking examples
   - Multiple task filtering examples
   - Complex conditions (AND/OR logic)

2. **Edge Cases**: Add examples for:
   - Missing fields (optional checks)
   - Array operations (checking all items)
   - Nested conditions
   - Using helper functions from `lib.tekton`

3. **Path Variations**: The example uses `buildDefinition.tasks` but most examples use `buildConfig.tasks`. Consider:
   - Adding more examples with `buildDefinition.tasks` path
   - Adding examples that handle both paths
   - Examples using helper functions that abstract path differences

4. **Error Handling**: Add examples showing:
   - Safe navigation patterns
   - Checking if fields exist before accessing
   - Default values

## Recommended Additions

### Additional Training Examples Needed

1. **Multiple Task Names**:
   ```json
   {"role": "user", "content": "Verify that either 'prefetch-dependencies' or 'prefetch-dependencies-oci-ta' task was not invoked with permissive mode."}
   ```

2. **Result Value Checking**:
   ```json
   {"role": "user", "content": "Verify that the build task's IMAGE_URL result contains 'quay.io'."}
   ```

3. **Label Checking**:
   ```json
   {"role": "user", "content": "Verify that all tasks have the label 'tekton.dev/memberOf' set to 'tasks'."}
   ```

4. **Multiple Conditions**:
   ```json
   {"role": "user", "content": "Verify that the build task succeeded and produced both IMAGE_URL and IMAGE_DIGEST results."}
   ```

5. **Using Helper Functions**:
   ```json
   {"role": "user", "content": "Verify that all tasks use trusted task references (using lib.tekton helpers)."}
   ```

6. **Safe Field Access**:
   ```json
   {"role": "user", "content": "Verify that if a task has a bundle reference, it contains a digest."}
   ```

## Training Recommendations

### 1. Data Augmentation
- Generate variations of existing examples with:
  - Different task names
  - Different parameter names
  - Different operators (==, !=, in, not in)
  - Different result messages

### 2. Validation
Before training, validate:
- All JSONL lines are valid JSON
- All examples have proper message structure
- Rego code is syntactically correct
- Examples cover the intended use cases

### 3. Training Parameters
For Qwen3 fine-tuning:
- **Learning Rate**: Start with 1e-5 to 5e-5
- **Batch Size**: Adjust based on GPU memory
- **Epochs**: 3-5 epochs typically sufficient
- **Warmup Steps**: 10% of total steps

### 4. Evaluation
Create a validation set with:
- Examples not in training data
- Edge cases
- Complex scenarios
- Real-world policy requirements

## File Structure

```
ec-policies/
├── qwen3-training-data.jsonl          # Main training file (JSONL format)
├── attestation-training-examples.json # Structured examples with metadata
├── attestation-structure-training-data.md # Documentation
└── qwen3-training-review.md          # This file
```

## Usage

### For Training:
```bash
# Use qwen3-training-data.jsonl directly with Qwen3 training scripts
python train_qwen3.py --train_file qwen3-training-data.jsonl
```

### For Reference:
- Use `attestation-structure-training-data.md` for understanding structure
- Use `attestation-training-examples.json` for programmatic example generation

## Next Steps

1. ✅ **Review Complete**: Training data format is correct
2. ⏳ **Add More Examples**: Expand to 20-30 examples for better coverage
3. ⏳ **Add Edge Cases**: Include examples for error handling and edge cases
4. ⏳ **Create Validation Set**: Separate 20% of examples for validation
5. ⏳ **Test Examples**: Validate all Rego code examples compile correctly

## Notes

- The training data correctly uses the `buildDefinition.tasks` path as shown in the original example
- System prompts include comprehensive context about both `buildConfig.tasks` and `buildDefinition.tasks` paths
- Examples are diverse enough to cover common patterns but could benefit from more edge cases
- All examples follow the same structure for consistency

## Example Quality

Each training example includes:
1. **System Message**: Context about attestation structure and patterns
2. **User Message**: Natural language policy requirement
3. **Assistant Message**: 
   - Complete Rego code in code blocks
   - Step-by-step explanation
   - Clear formatting

This format is optimal for Qwen3's instruction-following capabilities.
