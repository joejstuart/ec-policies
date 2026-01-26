#!/usr/bin/env python3
"""
Create Ollama Modelfile for fine-tuned Qwen3 Rego model.

This script generates a Modelfile for use with Ollama after converting
the model to GGUF format.

Usage:
    python create_ollama_modelfile.py --gguf-model ./qwen3-rego-finetuned.gguf --output Modelfile
"""

import argparse
from pathlib import Path


def create_modelfile(gguf_path: str, output_path: str, model_name: str = "qwen3-rego"):
    """Create Ollama Modelfile."""
    
    # Use raw strings and proper escaping for the template
    template_content = """<|im_start|>system
{{ .System }}<|im_end|>
{{- if .Prompt }}
<|im_start|>user
{{ .Prompt }}<|im_end|>
<|im_start|>assistant
{{- .Response }}<|im_end|>
{{- end }}"""
    
    system_prompt = """You are an expert at writing Rego policy rules for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code.

## Attestation Structure

The input structure is:
- `input.attestations` - array of attestation objects
- Each attestation has `statement.predicate` containing build information
- For SLSA v0.2: tasks are at `attestation.statement.predicate.buildConfig.tasks`
- For SLSA v1.0: tasks are at `attestation.statement.predicate.buildDefinition.resolvedDependencies`
- Alternative path (some formats): `attestation.statement.predicate.buildDefinition.tasks`

## Task Structure
- `task.name` - task name
- `task.invocation.parameters` - object with parameter key-value pairs
- `task.invocation.parameters.<param_name>` - specific parameter value
- `task.ref.bundle` - OCI bundle reference
- `task.results` - array of task results
- `task.status` - task status (e.g., "Succeeded")

## Common Patterns
- Iterate attestations: `some attestation in input.attestations`
- Iterate tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
- Filter by name: `task.name == "<name>"`
- Check parameter: `task.invocation.parameters.<param> == "<value>"`

Write Rego deny rules that check the attestation structure."""
    
    modelfile_content = f"""FROM {gguf_path}

# Model parameters
PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 3072

# Chat template for Qwen3 format
TEMPLATE \"\"\"{template_content}\"\"\"

# Stop tokens
STOP "<|im_end|>"
STOP "<|im_start|>"

# Default system prompt for Rego policy generation
SYSTEM \"\"\"{system_prompt}\"\"\"
"""
    
    output_file = Path(output_path)
    output_file.write_text(modelfile_content)
    
    print(f"✅ Modelfile created: {output_file}")
    print(f"\nTo create Ollama model:")
    print(f"  ollama create {model_name} -f {output_file}")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Create Ollama Modelfile for fine-tuned Qwen3 model"
    )
    parser.add_argument(
        "--gguf-model",
        type=str,
        required=True,
        help="Path to GGUF model file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="Modelfile",
        help="Output Modelfile path (default: Modelfile)"
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="qwen3-rego",
        help="Name for Ollama model (default: qwen3-rego)"
    )
    
    args = parser.parse_args()
    
    if not Path(args.gguf_model).exists():
        print(f"❌ Error: GGUF model not found: {args.gguf_model}")
        print("   Convert your model to GGUF first using llama.cpp")
        return 1
    
    create_modelfile(args.gguf_model, args.output, args.model_name)
    return 0


if __name__ == "__main__":
    exit(main())
