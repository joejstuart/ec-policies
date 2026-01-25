# Training Data Summary for Qwen3 Model

## Overview

This document summarizes the training data created for training a Qwen3 model to generate Rego policy rules from natural language descriptions of Enterprise Contract policy requirements.

## Files Created

### 1. `qwen3-training-data.jsonl` ⭐ **PRIMARY TRAINING FILE**
- **Format**: JSONL (JSON Lines) - one example per line
- **Structure**: Chat format with system/user/assistant messages
- **Examples**: 9 training examples
- **Status**: ✅ Validated - all JSON is properly formatted
- **Usage**: Use this file directly for Qwen3 fine-tuning

### 2. `attestation-training-examples.json`
- **Format**: Structured JSON with detailed metadata
- **Purpose**: Reference documentation with navigation steps
- **Use**: Can be used to programmatically generate more training examples

### 3. `attestation-structure-training-data.md`
- **Format**: Markdown documentation
- **Purpose**: Human-readable reference for attestation structure
- **Use**: Documentation for understanding JSON paths and structures

### 4. `qwen3-training-review.md`
- **Format**: Markdown review document
- **Purpose**: Quality assessment and recommendations
- **Use**: Review guide for training data improvements

## Training Data Structure

Each training example follows this format:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "System prompt with context about attestation structure..."
    },
    {
      "role": "user",
      "content": "Natural language policy requirement..."
    },
    {
      "role": "assistant",
      "content": "Rego code with explanation..."
    }
  ]
}
```

## Example Coverage

The training data includes examples for:

1. ✅ **Parameter Checking**: Verify task parameters (mode, sslVerify)
2. ✅ **Status Checking**: Verify task completion status
3. ✅ **Bundle Validation**: Verify trusted bundle references
4. ✅ **Result Validation**: Verify task results exist and have values
5. ✅ **Annotation Checking**: Verify task annotations
6. ✅ **Untagged Bundles**: Verify bundle references have digests
7. ✅ **Timestamp Validation**: Verify build timestamps

## Key Features

### System Prompt Includes:
- Complete attestation structure explanation
- Task structure details
- Common Rego patterns
- Path variations (SLSA v0.2, v1.0, alternative formats)

### Assistant Responses Include:
- Complete, syntactically correct Rego code
- Step-by-step explanations
- Code comments
- Proper formatting

## Validation

✅ **JSONL Format**: Validated - all lines are valid JSON  
✅ **Structure**: All examples follow correct message format  
✅ **Completeness**: Each example has system/user/assistant messages  
✅ **Code Quality**: Rego code examples are syntactically correct

## Usage Instructions

### For Training:
```bash
# Use the JSONL file directly with Qwen3 training scripts
python train_qwen3.py \
  --train_file qwen3-training-data.jsonl \
  --output_dir ./qwen3-finetuned \
  --learning_rate 2e-5 \
  --num_epochs 3
```

### For Review:
1. Read `qwen3-training-review.md` for quality assessment
2. Review `attestation-structure-training-data.md` for structure reference
3. Check `attestation-training-examples.json` for detailed examples

## Recommendations

### Immediate Use:
- ✅ Current training data is ready for initial training
- ✅ Format is correct for Qwen3
- ✅ Examples cover common patterns

### Future Improvements:
1. **Expand Examples**: Add 10-20 more examples for better coverage
2. **Edge Cases**: Add examples for error handling and edge cases
3. **Complex Scenarios**: Add examples with multiple conditions
4. **Helper Functions**: Add examples using `lib.tekton` helper functions
5. **Validation Set**: Create separate validation set (20% of examples)

## Statistics

- **Total Examples**: 9
- **Average Tokens per Example**: ~500-600
- **Code Examples**: All include complete Rego deny rules
- **Explanations**: All include step-by-step breakdowns

## Next Steps

1. ✅ **Training Data Created**: Ready for use
2. ⏳ **Expand Dataset**: Add more examples (recommended: 20-30 total)
3. ⏳ **Create Validation Set**: Split 20% for validation
4. ⏳ **Test Training**: Run initial training with current data
5. ⏳ **Evaluate Results**: Test model on validation set
6. ⏳ **Iterate**: Add more examples based on model performance

## Notes

- The training data correctly uses the `buildDefinition.tasks` path as shown in the original example
- System prompts include comprehensive context about path variations
- All examples follow consistent structure for optimal learning
- JSONL format is standard for Qwen3 fine-tuning

## Contact

For questions or improvements to the training data, refer to:
- `qwen3-training-review.md` for detailed review
- `attestation-structure-training-data.md` for structure reference
