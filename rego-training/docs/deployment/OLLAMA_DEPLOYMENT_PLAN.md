# Ollama Deployment Plan for Fine-tuned Qwen3 Model

## Overview

This plan outlines how to deploy your fine-tuned Qwen3 Rego policy generation model to Ollama for easy inference.

## Prerequisites

1. **Fine-tuned model** in HuggingFace format (from `finetune_qwen3.py`)
2. **Ollama installed** on your system
3. **Model conversion tools** (llama.cpp or similar)

## Challenges

1. **Format Conversion**: Ollama uses GGUF format, not PyTorch/HuggingFace
2. **LoRA Merging**: If using LoRA, need to merge adapters into base model
3. **Chat Template**: Need to match Qwen3's chat format (`<|im_start|>`, `<|im_end|>`)
4. **Model Size**: Qwen3-1.7B with LoRA merged is ~3.4GB

## Step-by-Step Plan

### Step 1: Merge LoRA Adapters (if used)

If you trained with LoRA, merge the adapters into the base model:

```bash
# Option A: Use PEFT to merge
python << EOF
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

base_model = "Qwen/Qwen3-1.7B"
adapter_path = "./qwen3-rego-finetuned"

# Load base model
model = AutoModelForCausalLM.from_pretrained(
    base_model,
    torch_dtype=torch.float16,
    device_map="auto"
)

# Load and merge LoRA
model = PeftModel.from_pretrained(model, adapter_path)
model = model.merge_and_unload()

# Save merged model
merged_path = "./qwen3-rego-finetuned-merged"
model.save_pretrained(merged_path)
tokenizer = AutoTokenizer.from_pretrained(adapter_path)
tokenizer.save_pretrained(merged_path)
print(f"✅ Merged model saved to {merged_path}")
EOF
```

### Step 2: Convert to GGUF Format

Ollama uses GGUF format. Convert using `llama.cpp`:

```bash
# Install llama.cpp
git clone https://github.com/ggerganov/llama.cpp.git
cd llama.cpp
make

# Convert HuggingFace model to GGUF
python convert-hf-to-gguf.py \
  --outfile qwen3-rego-finetuned.gguf \
  --outtype f16 \
  ./qwen3-rego-finetuned-merged
```

**Alternative**: Use `llama-cpp-python` or other conversion tools.

### Step 3: Create Ollama Modelfile

Create a `Modelfile` for your custom model:

```dockerfile
FROM ./qwen3-rego-finetuned.gguf

# Set model parameters
PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 3072

# Set system prompt template
TEMPLATE """<|im_start|>system
{{ .System }}<|im_end|>
{{- if .Prompt }}
<|im_start|>user
{{ .Prompt }}<|im_end|>
<|im_start|>assistant
{{- .Response }}<|im_end|>
{{- end }}"""

# Set stop tokens
STOP "<|im_end|>"
STOP "<|im_start|>"

# Set default system prompt for Rego generation
SYSTEM """You are an expert at writing Rego policy rules for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code.

## Attestation Structure

The input structure is:
- `input.attestations` - array of attestation objects
- Each attestation has `statement.predicate` containing build information
- For SLSA v0.2: tasks are at `attestation.statement.predicate.buildConfig.tasks`
- For SLSA v1.0: tasks are at `attestation.statement.predicate.buildDefinition.resolvedDependencies`

## Task Structure
- `task.name` - task name
- `task.invocation.parameters` - object with parameter key-value pairs
- `task.ref.bundle` - OCI bundle reference
- `task.results` - array of task results
- `task.status` - task status (e.g., "Succeeded")

Write Rego deny rules that check the attestation structure."""
```

### Step 4: Create Ollama Model

```bash
# Create model from Modelfile
ollama create qwen3-rego -f Modelfile

# Verify model
ollama list
```

### Step 5: Test the Model

```bash
# Test rule generation
ollama run qwen3-rego "Verify all tasks have status 'Succeeded'."

# Test with interactive mode
ollama run qwen3-rego
```

## Alternative Approaches

### Option A: Use Ollama's Import Feature

If Ollama supports direct HuggingFace import (check latest version):

```bash
ollama import ./qwen3-rego-finetuned
```

### Option B: Use Ollama's Python API

```python
import ollama

response = ollama.chat(
    model='qwen3-rego',
    messages=[
        {
            'role': 'system',
            'content': 'You are an expert at writing Rego policy rules...'
        },
        {
            'role': 'user',
            'content': 'Verify all tasks have status Succeeded.'
        }
    ]
)

print(response['message']['content'])
```

### Option C: Serve via Ollama API

```bash
# Start Ollama server
ollama serve

# Use REST API
curl http://localhost:11434/api/generate -d '{
  "model": "qwen3-rego",
  "prompt": "Verify all tasks have status Succeeded.",
  "stream": false
}'
```

## Scripts to Create

### 1. `merge_lora_adapters.py`

Script to merge LoRA adapters into base model.

### 2. `convert_to_ollama.py`

Script to convert HuggingFace model to GGUF and create Modelfile.

### 3. `test_ollama_model.py`

Script to test the Ollama model with sample prompts.

## Considerations

### Pros of Ollama Deployment

- ✅ Easy to use via CLI or API
- ✅ Automatic model management
- ✅ Built-in chat interface
- ✅ Good for local inference
- ✅ Supports multiple models

### Cons/Challenges

- ⚠️ Requires format conversion (GGUF)
- ⚠️ LoRA merging needed before conversion
- ⚠️ Chat template must match training format
- ⚠️ May need to adjust system prompts per use case

### Memory Requirements

- Model size: ~3.4GB (Qwen3-1.7B merged)
- Runtime memory: ~6-8GB for inference
- Ollama handles memory management automatically

## Testing Checklist

- [ ] Model converts successfully to GGUF
- [ ] Modelfile loads without errors
- [ ] Chat template matches training format
- [ ] Rule generation works correctly
- [ ] Test generation works correctly
- [ ] Both rule+test generation works
- [ ] System prompts are appropriate
- [ ] Stop tokens work correctly

## Next Steps

1. **Research current Ollama capabilities** - Check if direct HuggingFace import is supported
2. **Test conversion tools** - Verify llama.cpp or alternatives work with Qwen3
3. **Create conversion script** - Automate the process
4. **Test with sample prompts** - Verify output quality matches direct inference
5. **Document usage** - Create examples for different use cases

## Resources

- [Ollama Documentation](https://github.com/ollama/ollama)
- [llama.cpp](https://github.com/ggerganov/llama.cpp)
- [GGUF Format](https://github.com/ggerganov/ggml/blob/master/docs/gguf.md)
- [PEFT Merging](https://huggingface.co/docs/peft/package_reference/peft_model#peft.PeftModel.merge_and_unload)
