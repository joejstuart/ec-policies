# Migration Guide: Improved Tool Call Format

## Overview

We've updated the training data format to embed tool calls directly in the assistant's text content using an XML-style format. This makes tool calls parseable from the model's text output.

## What Changed

### Old Format
```json
{
  "role": "assistant",
  "content": "I'll read the file...",
  "tool_calls": [
    {
      "id": "call_abc123",
      "type": "function",
      "function": {
        "name": "read_file",
        "arguments": "{\"path\": \"file.txt\"}"
      }
    }
  ]
}
```

### New Format
```json
{
  "role": "assistant",
  "content": "I'll read the file to see its current contents.\n\n<tool_call>\nname: read_file\narguments: {\"path\": \"file.txt\"}\n</tool_call>"
}
```

The tool call is now **embedded in the text** in a parseable XML-style format.

## Migration Steps

### 1. Regenerate Training Data

**Generic Tool Usage Training:**
```bash
cd rego-training
python scripts/core/generate_generic_tool_usage_training.py \
    --output data/qwen3-generic-tool-usage-training-v2.jsonl
```

**File Editing Training:**
```bash
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

### 4. Test Inference

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-improved-tools \
    --interactive \
    --mode generic
```

## Tool Call Format

The new format uses XML-style tags:

```
<tool_call>
name: TOOL_NAME
arguments: {"key": "value"}
</tool_call>
```

### Example

```
I'll read the file to check its contents.

<tool_call>
name: read_file
arguments: {"path": "policy.rego"}
</tool_call>
```

## Parsing Logic

The inference script now parses this format first (before trying other formats):

```python
xml_pattern = r'<tool_call>\s*name:\s*(\w+)\s*arguments:\s*(\{.*?\})\s*</tool_call>'
```

This ensures reliable extraction of tool calls from the model's text output.

## Benefits

1. **Parseable**: Tool calls are in text, easy to extract with regex
2. **Reliable**: Clear format reduces ambiguity
3. **Model-Friendly**: Text format matches what models generate
4. **Backward Compatible**: Inference script still supports old formats

## Testing

After retraining, test with these prompts:

```
> create a file named test.txt
> add the content 'Hello' to the file test.txt
> read the file test.txt
```

The model should generate tool calls in the new XML format, which the inference script will parse and execute.

## Rollback

If you need to use the old format, the inference script still supports parsing JSON tool_calls arrays and other formats. However, the model will be trained on the new format, so it's recommended to use the new format going forward.
