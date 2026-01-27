# Tool-Supported Inference

This guide explains how to use the fine-tuned Qwen3 model with tool support for file editing operations.

## Overview

The `inference_qwen3_with_tools.py` script enables the model to:
- Read files using `read_file(path)` tool
- Write files using `write_file(path, contents)` tool
- Perform multi-step file editing operations
- Automatically execute tool calls and continue the conversation

## Installation

Same requirements as standard inference:
```bash
pip install transformers torch
```

## Basic Usage

### Edit a File

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-rego-finetuned \
    --prompt "Add a new rule to policy/release/example.rego: Verify all tasks have status Succeeded"
```

### Interactive Mode

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-rego-finetuned \
    --interactive
```

Then enter prompts like:
```
> Read the file at policy/release/example.rego and add a rule that checks task status
```

## How It Works

1. **Model generates response** with potential tool calls
2. **Script parses tool calls** from the model's text output
3. **Tools are executed** (read_file or write_file)
4. **Tool results are added** to the conversation
5. **Model generates next step** based on tool results
6. **Process repeats** until no more tool calls are needed

## Tool Call Formats

The model was trained to output tool calls in JSON format:

```json
{
  "tool_calls": [
    {
      "id": "call_abc123",
      "type": "function",
      "function": {
        "name": "read_file",
        "arguments": "{\"path\": \"policy/release/example.rego\"}"
      }
    }
  ]
}
```

The script can parse tool calls from:
- Structured JSON format (as above)
- Function call syntax: `read_file("path")`
- Natural language descriptions

## Example Workflow

### Adding a Rule to an Existing File

**User prompt:**
```
Add a new rule to policy/release/example.rego that verifies all tasks have status "Succeeded"
```

**Model behavior:**
1. Calls `read_file("policy/release/example.rego")`
2. Receives file contents
3. Generates updated file with new rule
4. Calls `write_file("policy/release/example.rego", updated_contents)`
5. Confirms completion

## Command-Line Options

### Required
- `--model`: Path to fine-tuned model directory

### Optional
- `--prompt`: Single user prompt (or use `--interactive`)
- `--interactive`: Run in interactive mode
- `--max-length`: Maximum input sequence length (default: 3072)
- `--temperature`: Sampling temperature (default: 0.7)
- `--top-p`: Top-p sampling (default: 0.9)
- `--device`: Device to use: auto, cpu, cuda (default: auto)
- `--verbose`: Show detailed tool execution output
- `--max-iterations`: Maximum tool call iterations (default: 10)

## Verbose Mode

Use `--verbose` to see detailed execution:

```bash
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-rego-finetuned \
    --prompt "Edit example.rego" \
    --verbose
```

Output shows:
- Each iteration of tool calls
- Detected tool calls
- Tool execution results
- Final response

## Limitations

1. **Tool Call Parsing**: The model outputs text, not structured JSON. The script attempts to parse tool calls from text, but may miss some formats.

2. **Multi-line Contents**: For `write_file`, extracting full file contents from text output can be challenging. The model should output tool calls in JSON format for best results.

3. **Error Handling**: If a tool call fails, the model will see the error message and can retry or adjust.

## Troubleshooting

### No Tool Calls Detected

If the model doesn't make tool calls:
- Check that the model was trained with tool usage data
- Try being more explicit: "Use the read_file tool to read..."
- Use `--verbose` to see what the model is outputting

### Tool Call Parsing Errors

If tool calls aren't being parsed correctly:
- The model may be outputting tool calls in an unexpected format
- Check the verbose output to see the raw model response
- Consider fine-tuning with more tool usage examples

### File Not Found

If `read_file` reports file not found:
- Ensure paths are relative to the current working directory
- Use absolute paths if needed
- Check file permissions

## Best Practices

1. **Be Explicit**: When asking for file operations, be clear about what you want:
   ```
   "Read the file at policy/release/example.rego and add a new rule..."
   ```

2. **Use Paths**: Always specify the file path clearly:
   ```
   "Edit policy/release/example.rego"
   ```

3. **Check Results**: Use `--verbose` to verify tool calls are being executed correctly.

4. **Iterative Editing**: The model can make multiple tool calls. Let it complete the full workflow.

## Integration with Training

This inference script works with models trained using:
- `generate_generic_tool_usage_training.py` (Track A: generic tool usage)
- `generate_file_editing_training_with_tools.py` (Track B: domain-specific editing)

The model learns to:
1. Recognize when tools are needed
2. Format tool calls correctly
3. Use tool results to continue the task
4. Complete multi-step operations
