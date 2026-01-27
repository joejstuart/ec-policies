# Two-Model Training Approach

## Overview

Instead of training a single model to do both rule generation and file operations, train two specialized models:

1. **Rule Generation Model**: Excellent at writing Rego rules from requirements
2. **File Operations Model**: Excellent at reading, editing, and writing files using tools

## Why Two Models?

### Challenges with Single Model

1. **Capacity Limits**: Small models struggle to excel at multiple distinct tasks
2. **Conflicting Patterns**: Rule generation (text-to-code) vs. tool usage (procedural) require different reasoning
3. **Training Data Mixing**: Mixing rule generation and tool usage can dilute learning
4. **Inference Complexity**: Tool calling adds overhead that may interfere with rule quality

### Benefits of Separation

1. **Focused Training**: Each model can be optimized for its specific task
2. **Better Performance**: Specialized models typically outperform generalist models
3. **Easier Debugging**: Issues are isolated to specific models
4. **Flexible Deployment**: Use rule generation model standalone, or combine with file operations
5. **Progressive Enhancement**: Start with rule generation, add file operations when needed

## Model Architecture

### Model 1: Rule Generation Model

**Purpose**: Generate Rego rules from natural language requirements

**Training Data**:
- `qwen3-training-data.jsonl` (rule generation examples)
- `qwen3-test-creation-training.jsonl` (test creation examples)
- **Total**: ~651 examples focused on Rego code generation

**System Prompt**: Domain-specific Rego knowledge (attestation structure, task patterns, etc.)

**Output**: Rego code (rules and tests)

**Use Case**: 
```python
# Standalone rule generation
rule = rule_model.generate("Verify all tasks succeeded")
```

### Model 2: File Operations Model

**Purpose**: Execute file operations using tools (read_file, write_file)

**Training Data**:
- `qwen3-generic-tool-usage-training.jsonl` (generic tool usage - Track A)
- `qwen3-file-editing-tools-training.jsonl` (domain-specific file editing - Track B)
- **Total**: ~480 + ~50-200 examples focused on tool usage

**System Prompt**: Generic tool usage instructions (no domain knowledge needed)

**Output**: Tool calls and file operations

**Use Case**:
```python
# File operations only
file_ops_model.edit_file("policy/release/example.rego", "Add a new rule here")
```

## Hybrid Approach: Orchestration

Combine both models in a workflow:

```python
def add_rule_to_file(requirement: str, file_path: str):
    # Step 1: Generate the rule using rule generation model
    rule_code = rule_model.generate(requirement)
    
    # Step 2: Read existing file
    existing_content = read_file(file_path)
    
    # Step 3: Use file operations model to integrate the rule
    updated_content = file_ops_model.integrate_rule(existing_content, rule_code)
    
    # Step 4: Write the file
    write_file(file_path, updated_content)
```

Or use a simple orchestrator:

```python
def orchestrate_rule_addition(requirement: str, file_path: str):
    # Generate rule
    rule = rule_model.generate(requirement)
    
    # Use file ops model to add it to file
    file_ops_model.execute(
        f"Read {file_path}, add this rule: {rule}, and save the file"
    )
```

## Training Strategy

### Rule Generation Model

**Focus**: Code generation quality

```bash
python finetune_qwen3.py \
    --training-data data/qwen3-rule-generation-only.jsonl \
    --model Qwen/Qwen2.5-0.5B \
    --output-dir ./qwen3-rule-generator \
    --epochs 5 \
    --max-length 2048  # Rules are shorter, can use smaller context
```

**Training Data**: Only rule generation and test creation examples

### File Operations Model

**Focus**: Tool usage reliability

```bash
python finetune_qwen3.py \
    --training-data data/qwen3-file-operations-only.jsonl \
    --model Qwen/Qwen2.5-0.5B \
    --output-dir ./qwen3-file-ops \
    --epochs 5 \
    --max-length 3072  # File contents can be long
```

**Training Data**: Only generic tool usage and file editing examples

## Creating Separate Training Datasets

### Rule Generation Only

```bash
python scripts/core/merge_training_data.py \
    --rule-data data/qwen3-training-data.jsonl \
    --test-data data/qwen3-test-creation-training.jsonl \
    --output data/qwen3-rule-generation-only.jsonl
```

### File Operations Only

```bash
python scripts/core/merge_training_data.py \
    --generic-tool-data data/qwen3-generic-tool-usage-training.jsonl \
    --file-editing-data data/qwen3-file-editing-tools-training.jsonl \
    --output data/qwen3-file-operations-only.jsonl
```

## Comparison: Single vs. Two Models

| Aspect | Single Model | Two Models |
|--------|--------------|------------|
| **Training Complexity** | One training run | Two training runs |
| **Model Size** | One model | Two models (same total size) |
| **Rule Quality** | May be diluted | Focused, optimized |
| **Tool Reliability** | May struggle | Specialized, reliable |
| **Deployment** | One model to manage | Two models to orchestrate |
| **Flexibility** | All-in-one | Can use independently |
| **Best For** | Large models (7B+) | Small models (<3B) |

## Recommended Approach for Small Models

**Use Two Models** if:
- Model size < 3B parameters
- Rule generation quality is critical
- File operations need to be reliable
- You can handle orchestration complexity

**Use Single Model** if:
- Model size >= 7B parameters
- You want simpler deployment
- Tool usage is infrequent
- You're okay with trade-offs

## Implementation Example

### Simple Orchestrator Script

```python
#!/usr/bin/env python3
"""
Orchestrate rule generation and file operations using two specialized models.
"""

from inference_qwen3 import generate as generate_rule
from inference_qwen3_with_tools import generate_with_tools

def add_rule_to_file(requirement: str, file_path: str, 
                     rule_model_path: str, file_ops_model_path: str):
    """
    Add a rule to a file using two specialized models.
    """
    # Step 1: Generate the rule
    print("Generating rule...")
    rule_code = generate_rule(
        model=load_model(rule_model_path),
        tokenizer=load_tokenizer(rule_model_path),
        system_prompt=get_rego_system_prompt(),
        user_prompt=requirement
    )
    
    # Step 2: Use file operations model to add it
    print("Adding rule to file...")
    prompt = f"""Read the file at {file_path}, add this new rule after the existing deny rules, and save the file.

New rule to add:
```rego
{rule_code}
```
"""
    
    messages = [
        {"role": "system", "content": get_file_ops_system_prompt()},
        {"role": "user", "content": prompt}
    ]
    
    final_messages, response = generate_with_tools(
        model=load_model(file_ops_model_path),
        tokenizer=load_tokenizer(file_ops_model_path),
        messages=messages
    )
    
    return response
```

## Migration Path

If you currently have a combined model:

1. **Evaluate**: Test rule generation quality vs. file operations quality
2. **Split Data**: Create separate training datasets
3. **Train Rule Model**: Focus on code generation
4. **Train File Ops Model**: Focus on tool usage
5. **Build Orchestrator**: Combine both models
6. **Compare**: Test two-model approach vs. single model

## Conclusion

For small models (<3B), **two specialized models** will likely outperform a single generalist model. The added complexity of orchestration is worth the improved quality and reliability in each domain.
