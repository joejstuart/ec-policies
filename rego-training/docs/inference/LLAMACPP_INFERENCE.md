# Running Fine-Tuned Model with llama.cpp

This guide explains how to convert your fine-tuned Qwen3 model to GGUF format and run it with llama.cpp.

## Overview

llama.cpp is a C++ implementation that provides:
- **Faster inference** (especially on CPU)
- **Lower memory usage**
- **Better performance** on Apple Silicon (M1/M2/M3)
- **No Python dependencies** for inference

## Relationship to Ollama

**Yes, it's the same format!** Both llama.cpp and Ollama:
- Use the same **GGUF model format**
- Use the same **Qwen3 chat format** (`<|im_start|>`, `<|im_end|>` tokens)
- Can use the same converted model file

**The difference:**
- **llama.cpp**: You format prompts manually in code
- **Ollama**: The Modelfile template handles formatting automatically

If you've already set up Ollama, you can use the same GGUF file with llama.cpp directly (or vice versa).

## Prerequisites

1. **Fine-tuned model** in HuggingFace format (saved by `finetune_qwen3.py`)
2. **llama.cpp** installed and built
3. **llama-cpp-python** (Python bindings) OR use `llama.cpp` directly

## Step 1: Install llama.cpp

### Option A: Build from source (recommended)

```bash
# Clone llama.cpp
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp

# Build (adjust for your platform)
make

# Or for Apple Silicon:
make LLAMA_METAL=1

# Or for CUDA:
make LLAMA_CUBLAS=1
```

### Option B: Install Python bindings

```bash
pip install llama-cpp-python

# For Apple Silicon:
CMAKE_ARGS="-DLLAMA_METAL=on" pip install llama-cpp-python

# For CUDA:
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python
```

## Step 2: Convert Model to GGUF Format

Your fine-tuned model is saved in HuggingFace format. Convert it to GGUF:

### Install conversion script

```bash
# Install llama.cpp Python dependencies
cd llama.cpp
pip install -r requirements.txt
```

### Convert the model

```bash
# Basic conversion
python llama.cpp/convert_hf_to_gguf.py \
    ./qwen3-rego-finetuned \
    --outdir ./qwen3-rego-finetuned-gguf \
    --outtype f16

# For quantization (smaller, faster):
# After conversion, quantize:
./llama.cpp/quantize \
    ./qwen3-rego-finetuned-gguf/ggml-model-f16.gguf \
    ./qwen3-rego-finetuned-gguf/ggml-model-q4_0.gguf \
    q4_0
```

### Quantization Options

- `q4_0` - 4-bit, smallest, fastest (recommended for testing)
- `q4_1` - 4-bit, slightly better quality
- `q5_0` - 5-bit, better quality
- `q5_1` - 5-bit, slightly better
- `q8_0` - 8-bit, best quality, larger
- `f16` - 16-bit float, no quantization (largest, best quality)

## Step 3: Run Inference

### Option A: Using llama.cpp directly

```bash
# Basic inference
./llama.cpp/main \
    -m ./qwen3-rego-finetuned-gguf/ggml-model-q4_0.gguf \
    -p "Your prompt here" \
    -n 512 \
    --temp 0.7

# Interactive mode
./llama.cpp/main \
    -m ./qwen3-rego-finetuned-gguf/ggml-model-q4_0.gguf \
    -i \
    -n 512 \
    --temp 0.7
```

### Option B: Using Python bindings

```python
from llama_cpp import Llama

# Load model
llm = Llama(
    model_path="./qwen3-rego-finetuned-gguf/ggml-model-q4_0.gguf",
    n_ctx=2048,  # Context window
    n_threads=4,  # CPU threads
    verbose=True
)

# Generate
response = llm(
    "Your prompt here",
    max_tokens=512,
    temperature=0.7,
    stop=["<|im_end|>", "<|im_start|>"]
)

print(response["choices"][0]["text"])
```

## Step 4: Handle Qwen3 Chat Format

Qwen3 uses a specific chat format. You need to format prompts correctly:

```python
def format_qwen3_prompt(system_prompt: str, user_prompt: str) -> str:
    """Format prompt for Qwen3 chat format."""
    return f"""<|im_start|>system
{system_prompt}<|im_end|>
<|im_start|>user
{user_prompt}<|im_end|>
<|im_start|>assistant
"""

# Use it
prompt = format_qwen3_prompt(
    system_prompt="You are a helpful assistant.",
    user_prompt="Generate a Rego rule to verify all tasks succeed."
)

response = llm(prompt, max_tokens=512, temperature=0.7)
```

**Note**: This is the same format used by Ollama! The only difference is:
- **llama.cpp**: You format the prompt manually in code
- **Ollama**: The Modelfile template handles formatting automatically

Both use the same underlying Qwen3 chat format with `<|im_start|>` and `<|im_end|>` tokens.

## Step 5: Tool Calling with llama.cpp

Your model was trained to generate tool calls in XML format. You'll need to:

1. **Parse tool calls** from the model output (same as your current inference script)
2. **Execute tools** (read_file, write_file)
3. **Continue conversation** with tool responses

### Example: Tool-Supported Inference

```python
from llama_cpp import Llama
import json
import re

llm = Llama(
    model_path="./qwen3-rego-finetuned-gguf/ggml-model-q4_0.gguf",
    n_ctx=3072,  # Larger context for tool calls
    verbose=True
)

def parse_tool_calls(text: str) -> list:
    """Parse XML-style tool calls from model output."""
    tool_calls = []
    pattern = r'<tool_call>\s*name:\s*(\w+)\s*arguments:\s*(\{.*?\})\s*</tool_call>'
    for match in re.finditer(pattern, text, re.DOTALL):
        tool_name = match.group(1)
        args_str = match.group(2)
        try:
            arguments = json.loads(args_str)
            tool_calls.append({
                "name": tool_name,
                "arguments": arguments
            })
        except json.JSONDecodeError:
            pass
    return tool_calls

def execute_tool(tool_call: dict) -> str:
    """Execute a tool call."""
    name = tool_call["name"]
    args = tool_call["arguments"]
    
    if name == "read_file":
        path = args.get("path")
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error: {e}"
    
    elif name == "write_file":
        path = args.get("path")
        contents = args.get("contents", "")
        try:
            with open(path, 'w') as f:
                f.write(contents)
            return "File written successfully."
        except Exception as e:
            return f"Error: {e}"
    
    return f"Unknown tool: {name}"

# Multi-turn conversation with tools
messages = [
    {"role": "system", "content": "Your system prompt here"},
    {"role": "user", "content": "Read the file at example.txt"}
]

max_iterations = 10
for i in range(max_iterations):
    # Format messages
    prompt = format_qwen3_prompt(
        messages[0]["content"],
        messages[-1]["content"]
    )
    
    # Generate
    response = llm(prompt, max_tokens=512, temperature=0.7, stop=["<|im_end|>"])
    assistant_text = response["choices"][0]["text"]
    
    # Check for tool calls
    tool_calls = parse_tool_calls(assistant_text)
    
    if not tool_calls:
        # No tools, conversation done
        print(f"Final response: {assistant_text}")
        break
    
    # Execute tools
    for tool_call in tool_calls:
        result = execute_tool(tool_call)
        messages.append({
            "role": "assistant",
            "content": assistant_text
        })
        messages.append({
            "role": "tool",
            "content": result
        })
        
        # Continue conversation with tool result
        prompt = format_qwen3_prompt(
            messages[0]["content"],
            f"{messages[-2]['content']}\nTool result: {result}"
        )
```

## Complete Inference Script

Create `inference_llamacpp.py`:

```python
#!/usr/bin/env python3
"""Run inference with llama.cpp and tool support."""

import argparse
import json
import re
from pathlib import Path
from llama_cpp import Llama

def format_qwen3_prompt(system: str, user: str) -> str:
    return f"""<|im_start|>system
{system}<|im_end|>
<|im_start|>user
{user}<|im_end|>
<|im_start|>assistant
"""

def parse_tool_calls(text: str) -> list:
    """Parse XML-style tool calls."""
    tool_calls = []
    pattern = r'<tool_call>\s*name:\s*(\w+)\s*arguments:\s*(\{.*?\})\s*</tool_call>'
    for match in re.finditer(pattern, text, re.DOTALL):
        try:
            tool_calls.append({
                "name": match.group(1),
                "arguments": json.loads(match.group(2))
            })
        except:
            pass
    return tool_calls

def execute_tool(tool_call: dict) -> str:
    """Execute tool call."""
    name = tool_call["name"]
    args = tool_call["arguments"]
    
    if name == "read_file":
        path = Path(args["path"])
        if path.exists():
            return path.read_text()
        return f"Error: File not found: {args['path']}"
    
    elif name == "write_file":
        path = Path(args["path"])
        path.write_text(args.get("contents", ""))
        return "File written successfully."
    
    return f"Unknown tool: {name}"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, help="Path to GGUF model")
    parser.add_argument("--prompt", help="Single prompt")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--n-ctx", type=int, default=3072)
    parser.add_argument("--n-threads", type=int, default=4)
    args = parser.parse_args()
    
    # Load model
    llm = Llama(
        model_path=args.model,
        n_ctx=args.n_ctx,
        n_threads=args.n_threads,
        verbose=True
    )
    
    system_prompt = "Your system prompt here"
    
    if args.prompt:
        # Single prompt
        prompt = format_qwen3_prompt(system_prompt, args.prompt)
        response = llm(prompt, max_tokens=512, temperature=0.7)
        print(response["choices"][0]["text"])
    
    elif args.interactive:
        # Interactive mode
        print("Interactive mode (type 'quit' to exit)")
        while True:
            user_input = input("\n> ")
            if user_input.lower() == "quit":
                break
            
            prompt = format_qwen3_prompt(system_prompt, user_input)
            response = llm(prompt, max_tokens=512, temperature=0.7)
            text = response["choices"][0]["text"]
            
            # Check for tool calls
            tool_calls = parse_tool_calls(text)
            if tool_calls:
                print(f"\n🔧 Executing {len(tool_calls)} tool call(s)...")
                for tool_call in tool_calls:
                    result = execute_tool(tool_call)
                    print(f"  {tool_call['name']}: {result}")
            else:
                print(f"\n{text}")

if __name__ == "__main__":
    main()
```

## Usage

```bash
# Convert model
python llama.cpp/convert_hf_to_gguf.py \
    ./qwen3-rego-finetuned \
    --outdir ./qwen3-rego-finetuned-gguf \
    --outtype f16

# Quantize (optional)
./llama.cpp/quantize \
    ./qwen3-rego-finetuned-gguf/ggml-model-f16.gguf \
    ./qwen3-rego-finetuned-gguf/ggml-model-q4_0.gguf \
    q4_0

# Run inference
python inference_llamacpp.py \
    --model ./qwen3-rego-finetuned-gguf/ggml-model-q4_0.gguf \
    --interactive
```

## Notes

1. **LoRA models**: If you used LoRA, you need to merge the LoRA weights before conversion:
   ```python
   from peft import PeftModel
   from transformers import AutoModelForCausalLM
   
   base_model = AutoModelForCausalLM.from_pretrained("Qwen/Qwen2.5-0.5B")
   model = PeftModel.from_pretrained(base_model, "./qwen3-rego-finetuned")
   merged_model = model.merge_and_unload()
   merged_model.save_pretrained("./qwen3-rego-finetuned-merged")
   ```

2. **Context window**: Set `n_ctx` to match your training `max_length` (3072 in your case)

3. **Temperature**: Use 0.7 for creative tasks, 0.1-0.3 for deterministic tool calling

4. **Stop tokens**: Always include `["<|im_end|>", "<|im_start|>"]` in stop tokens

## Troubleshooting

- **Model not found**: Make sure the GGUF file path is correct
- **Out of memory**: Use a smaller quantization (q4_0) or reduce `n_ctx`
- **Wrong format**: Ensure you're using Qwen3 chat format with `<|im_start|>` tokens
- **Tool calls not parsed**: Check that your model output matches the XML format from training
