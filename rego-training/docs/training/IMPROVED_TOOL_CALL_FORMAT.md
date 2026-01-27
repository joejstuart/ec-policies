# Improved Tool Call Format for Training

## Problem

The current training data has tool calls as a **separate JSON key** (`tool_calls`), but during inference, the model only generates **text**. This mismatch causes the model to generate text descriptions instead of parseable tool calls.

## Solution: Parseable Text Format

Train the model to output tool calls in a **parseable text format** that can be easily extracted from the generated text.

## New Format Design

### Format 1: XML-Style (Recommended)

```
<tool_call>
name: read_file
arguments: {"path": "file.txt"}
</tool_call>
```

**Pros:**
- ✅ Easy to parse with regex
- ✅ Clear delimiters
- ✅ Can appear anywhere in text
- ✅ Human-readable

**Cons:**
- ❌ Model might generate malformed XML
- ❌ Need to handle edge cases

### Format 2: JSON Block

```
```json
{"tool": "read_file", "arguments": {"path": "file.txt"}}
```
```

**Pros:**
- ✅ Standard JSON format
- ✅ Easy to parse
- ✅ Can validate

**Cons:**
- ❌ Model might generate invalid JSON
- ❌ Code block markers might confuse model

### Format 3: Simple Structured Text

```
TOOL_CALL_START
tool: read_file
arguments: {"path": "file.txt"}
TOOL_CALL_END
```

**Pros:**
- ✅ Very clear delimiters
- ✅ Easy to parse
- ✅ Unambiguous

**Cons:**
- ❌ Less natural
- ❌ Might feel "artificial"

## Chosen Format: XML-Style with Fallback

We'll use **Format 1 (XML-style)** because:
1. It's natural and readable
2. Easy to parse with regex
3. Can handle multiple tool calls
4. Works well with text generation models

### Example Training Data

**Before (current format):**
```json
{
  "role": "assistant",
  "content": "I'll read the file...",
  "tool_calls": [{"id": "...", "function": {...}}]
}
```

**After (new format):**
```json
{
  "role": "assistant",
  "content": "I'll read the file to see its current contents.\n\n<tool_call>\nname: read_file\narguments: {\"path\": \"file.txt\"}\n</tool_call>"
}
```

The model learns to output tool calls **in the text** in a parseable format.

## Implementation Plan

1. **Update training data generation scripts** to use new format
2. **Regenerate all training data** (generic tool usage + file editing)
3. **Update inference script** to parse new format
4. **Retrain model** with new data
5. **Test and validate** tool call parsing

## Parsing Logic

```python
import re
import json

def parse_tool_calls_from_text(text: str) -> List[Dict]:
    """Parse tool calls from model-generated text."""
    tool_calls = []
    
    # Pattern: <tool_call>...name: TOOL_NAME\narguments: {...}...</tool_call>
    pattern = r'<tool_call>\s*name:\s*(\w+)\s*arguments:\s*(\{.*?\})\s*</tool_call>'
    
    matches = re.finditer(pattern, text, re.DOTALL)
    for match in matches:
        tool_name = match.group(1)
        args_str = match.group(2)
        
        try:
            arguments = json.loads(args_str)
            tool_calls.append({
                "name": tool_name,
                "arguments": arguments
            })
        except json.JSONDecodeError:
            # Try to fix common JSON issues
            # (handle trailing commas, unquoted keys, etc.)
            pass
    
    return tool_calls
```

## Training Data Updates

### Generic Tool Usage Training

Update `generate_generic_tool_usage_training.py`:
- Change assistant content to include tool calls in text
- Remove `tool_calls` key from message (or keep for compatibility)
- Ensure format is consistent across all examples

### File Editing Training

Update `generate_file_editing_training_with_tools.py`:
- Same changes as above
- Ensure Rego-specific examples use new format

## Benefits

1. **Better Parsing**: Tool calls are in text, easy to extract
2. **More Reliable**: Clear format reduces ambiguity
3. **Model-Friendly**: Text format matches what models generate
4. **Backward Compatible**: Can still parse old format if needed

## Migration Steps

1. Generate new training data with improved format
2. Merge with existing rule generation data
3. Retrain model
4. Update inference script
5. Test end-to-end
