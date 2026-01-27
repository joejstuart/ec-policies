# File Edit Workflow Implementation Status

## ✅ Completed (Phase 1 & 2)

### Phase 1: Training Data Updates

1. **System Prompts Updated**:
   - ✅ Added explicit workflow steps: read → reason → generate complete content → write
   - ✅ Emphasized "COMPLETE file content" not "diffs or patches"
   - ✅ Updated both generic and Rego-specific prompts

2. **Training Examples Updated**:
   - ✅ Changed assistant messages to say "generate the complete updated file content"
   - ✅ Removed language that might suggest diff/patch operations
   - ✅ All examples show full file content in `write_file` tool calls

3. **Files Modified**:
   - ✅ `generate_generic_tool_usage_training.py` - System prompt updated
   - ✅ `generate_file_editing_training_with_tools.py` - System prompt and examples updated

### Phase 2: Inference Script Updates

1. **Workflow Validation Added**:
   - ✅ Checks if `write_file` is called without `read_file` first (warns in verbose mode)
   - ✅ Validates that `write_file` content doesn't look like a diff/patch
   - ✅ Warns when natural language inference is used (indicates training needed)

2. **Natural Language Inference**:
   - ✅ Added warnings when inference is used (logged for debugging)
   - ✅ Still available as fallback, but clearly marked as suboptimal

3. **System Prompts**:
   - ✅ Updated `get_system_prompt_with_tools()` to match training data
   - ✅ Added explicit workflow steps and "complete content" emphasis

4. **Files Modified**:
   - ✅ `inference_qwen3_with_tools.py` - Validation, warnings, and prompts updated

## 📋 Next Steps

### Immediate Actions

1. **Regenerate Training Data**:
   ```bash
   # Generic tool usage
   python scripts/core/generate_generic_tool_usage_training.py \
       --output data/qwen3-generic-tool-usage-training-v4.jsonl
   
   # File editing
   python scripts/core/generate_file_editing_training_with_tools.py \
       --output data/qwen3-file-editing-training-v2.jsonl
   ```

2. **Merge and Retrain**:
   ```bash
   python scripts/core/merge_training_data.py \
       --rule-data data/qwen3-complete-training.jsonl \
       --generic-tool-data data/qwen3-generic-tool-usage-training-v4.jsonl \
       --file-editing-data data/qwen3-file-editing-training-v2.jsonl \
       --output data/qwen3-complete-with-workflow-v1.jsonl
   
   python scripts/core/finetune_qwen3.py \
       --base-model Qwen/Qwen2.5-0.5B \
       --training-data data/qwen3-complete-with-workflow-v1.jsonl \
       --output-dir ./qwen3-workflow-v1 \
       --max-length 3072
   ```

3. **Test the Retrained Model**:
   ```bash
   python scripts/core/inference_qwen3_with_tools.py \
       --model ./qwen3-workflow-v1 \
       --interactive \
       --mode generic \
       --verbose
   ```

### Future Improvements

1. **Phase 3**: Add more validation
   - Check that `write_file` content length is reasonable (not too short for large files)
   - Verify content structure matches expected format

2. **Phase 4**: Consider hybrid approach
   - Use deterministic tools for simple operations
   - Use model only for complex content generation

3. **Phase 5**: Testing
   - Create comprehensive test suite
   - Validate workflow compliance
   - Measure success rates

## Key Changes Summary

### Training Data
- **Before**: Examples might suggest partial updates or diffs
- **After**: All examples explicitly show complete file content generation

### Inference Script
- **Before**: Silent natural language inference, no validation
- **After**: Warnings when inference used, workflow validation, clear errors

### System Prompts
- **Before**: Generic guidelines
- **After**: Explicit workflow steps, "complete content" emphasis

## Expected Improvements

After retraining with the updated data:
1. ✅ Model should generate tool calls more consistently
2. ✅ Model should generate complete file content (not diffs)
3. ✅ Model should follow the correct workflow (read → reason → write)
4. ✅ Less content inference from training examples
5. ✅ Better error messages when workflow isn't followed

## Monitoring

When testing the retrained model, watch for:
- Tool call generation rate (should be high)
- Natural language inference warnings (should be rare)
- Workflow validation warnings (should be none)
- Content quality (complete files, not partial)
