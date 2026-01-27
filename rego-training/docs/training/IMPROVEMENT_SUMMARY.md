# Tool Call Format Improvement - Summary

## What We Did

We've improved the training data format to make tool calls **parseable from text output**. This addresses the core issue where the model was generating text descriptions instead of executable tool calls.

## Changes Made

### 1. Updated Training Data Generation

**Files Modified:**
- `scripts/core/generate_generic_tool_usage_training.py`
- `scripts/core/generate_file_editing_training_with_tools.py`

**Change:** Tool calls are now embedded in the assistant's text content using XML-style format:

```
<tool_call>
name: read_file
arguments: {"path": "file.txt"}
</tool_call>
```

### 2. Updated Inference Script

**File Modified:**
- `scripts/core/inference_qwen3_with_tools.py`

**Change:** Added parsing logic to extract XML-style tool calls from model output. This is now the **first** format tried (highest priority).

### 3. Created Documentation

- `docs/training/IMPROVED_TOOL_CALL_FORMAT.md` - Format specification
- `docs/training/MIGRATION_GUIDE.md` - Step-by-step migration instructions
- `docs/training/IMPROVEMENT_SUMMARY.md` - This file

## Next Steps

### 1. Regenerate Training Data

```bash
cd rego-training

# Generate new generic tool usage data
python scripts/core/generate_generic_tool_usage_training.py \
    --output data/qwen3-generic-tool-usage-training-v2.jsonl

# Generate new file editing data
python scripts/core/generate_file_editing_training_with_tools.py \
    --output data/qwen3-file-editing-training-v2.jsonl
```

### 2. Merge with Existing Data

```bash
python scripts/core/merge_training_data.py \
    --rule-data data/qwen3-complete-training.jsonl \
    --generic-tool-data data/qwen3-generic-tool-usage-training-v2.jsonl \
    --file-editing-data data/qwen3-file-editing-training-v2.jsonl \
    --output data/qwen3-complete-with-improved-tools.jsonl
```

### 3. Retrain Model

```bash
python scripts/core/finetune_qwen3.py \
    --base-model Qwen/Qwen2.5-0.5B \
    --training-data data/qwen3-complete-with-improved-tools.jsonl \
    --output-dir ./qwen3-improved-tools \
    --max-length 3072
```

### 4. Test

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-improved-tools \
    --interactive \
    --mode generic
```

## Expected Improvements

After retraining, the model should:

1. ✅ Generate tool calls in the XML format consistently
2. ✅ Have tool calls parsed reliably by the inference script
3. ✅ Execute file operations correctly
4. ✅ Work better with multi-step operations (read → modify → write)

## Format Comparison

### Old Format (Separate Key)
```json
{
  "content": "I'll read the file...",
  "tool_calls": [{"id": "...", "function": {...}}]
}
```
**Problem:** Model only generates text, can't output separate keys.

### New Format (Embedded in Text)
```json
{
  "content": "I'll read the file...\n\n<tool_call>\nname: read_file\narguments: {...}\n</tool_call>"
}
```
**Solution:** Tool calls are in text, parseable with regex.

## Benefits

1. **Reliable Parsing**: XML format is easy to extract with regex
2. **Model-Friendly**: Text format matches what models generate
3. **Clear Delimiters**: `<tool_call>` tags are unambiguous
4. **Backward Compatible**: Inference script still supports old formats

## Testing Checklist

After retraining, test these scenarios:

- [ ] Create a new file
- [ ] Read an existing file
- [ ] Add content to a file
- [ ] Edit file content
- [ ] Multi-step operations (read → modify → write)
- [ ] Handle errors gracefully

## Notes

- The inference script tries XML format first, then falls back to other formats
- Training data still includes `tool_call_id` for tool responses (for conversation flow)
- The model learns to generate tool calls in text, not as separate JSON keys
