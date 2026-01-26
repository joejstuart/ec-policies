# Two-Track Training Approach

This document explains the recommended two-track training approach for teaching file editing with tools.

## Why Two Tracks?

Teaching tool usage and domain knowledge separately has several advantages:

1. **Clearer Learning**: Model learns tool usage patterns first, then adds domain expertise
2. **Better Generalization**: Tool usage skills transfer to other domains
3. **Easier Debugging**: Can test tool usage independently of domain logic
4. **Modular Training**: Can update domain knowledge without retraining tool usage

## Track A: Generic Tool Usage

### Purpose
Teach the model pure procedural correctness for file editing:
- Read file → Modify → Write file
- Follow user instructions precisely
- No domain inference
- No style guide application

### Characteristics

**System Prompt:**
```
Your job is to edit files using tools exactly as the user instructs.
Do not infer missing logic. Do not create domain-specific content.
Only manipulate the text the user describes.
```

**Training Examples:**
- Simple text file edits
- Line replacements
- Insertions/deletions
- Text replacements
- No domain knowledge required

**Example Training Trajectory:**
```
User: "Edit example.txt. Replace line 3 with 'Updated line'"

Assistant: I'll read the file, make the change, and save it.

<tool_call>
<function=read_file>
<parameter=path>
example.txt
</parameter>
</function>
</tool_call>

<tool_response>
Line 1: First line
Line 2: Second line
Line 3: Third line
Line 4: Fourth line
</tool_response>

Now I'll make the requested changes and save the file:

<tool_call>
<function=write_file>
<parameter=path>
example.txt
</parameter>
<parameter=contents>
Line 1: First line
Line 2: Second line
Line 3: Updated line
Line 4: Fourth line
</parameter>
</function>
</tool_call>

<tool_response>
File written successfully.
</tool_response>

Done.
```

### Generating Track A Data

```bash
python scripts/core/generate_generic_tool_usage_training.py
```

Output: `data/qwen3-generic-tool-usage-training.jsonl`

### Training Track A

```bash
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-generic-tool-usage-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-tool-usage-base \
  --epochs 3
```

## Track B: Domain-Specific File Editing

### Purpose
Teach the model domain-specific editing for Rego policy files:
- Rego syntax and structure
- Attestation format knowledge
- Rule placement conventions
- METADATA annotations
- Package/import management

### Characteristics

**System Prompt:**
```
You are an expert at writing Rego policy rules for Enterprise Contract.
[Includes domain-specific knowledge about attestations, tasks, etc.]

When adding a new rule to an existing policy file:
1. First, read the existing file using the read_file tool
2. Keep the existing package declaration and imports
3. Add the new rule after existing deny rules
4. Place helper rules (starting with _) after all deny rules
...
```

**Training Examples:**
- Rego policy file edits
- Adding deny rules
- Maintaining file structure
- Domain-specific patterns

### Generating Track B Data

```bash
python scripts/core/generate_file_editing_training_with_tools.py
```

Output: `data/qwen3-file-editing-tools-training.jsonl`

### Training Track B (on top of Track A)

```bash
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-file-editing-tools-training.jsonl \
  --model ./qwen3-tool-usage-base \
  --output-dir ./qwen3-rego-file-editing \
  --epochs 3
```

## Complete Training Workflow

### Step 1: Generate Training Data

```bash
# Track A: Generic tool usage
python scripts/core/generate_generic_tool_usage_training.py

# Track B: Domain-specific editing
python scripts/core/generate_file_editing_training_with_tools.py
```

### Step 2: Train Track A

```bash
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-generic-tool-usage-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-tool-usage-base \
  --epochs 3 \
  --batch-size 4
```

### Step 3: Train Track B (Fine-tune Track A model)

```bash
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-file-editing-tools-training.jsonl \
  --model ./qwen3-tool-usage-base \
  --output-dir ./qwen3-rego-file-editing \
  --epochs 3 \
  --batch-size 4
```

### Step 4: Use the Final Model

```bash
python scripts/core/inference_qwen3.py \
  --model ./qwen3-rego-file-editing \
  --mode file-editing
```

## Benefits of Two-Track Approach

1. **Separation of Concerns**: Tool usage vs domain knowledge
2. **Reusability**: Track A model can be used for other domains
3. **Easier Testing**: Test tool usage independently
4. **Incremental Learning**: Build skills layer by layer
5. **Better Debugging**: Isolate issues to tool usage or domain logic

## Alternative: Single-Track Approach

If you prefer to train everything at once:

```bash
# Merge both training datasets
python scripts/core/merge_training_data.py \
  --rule-data data/qwen3-generic-tool-usage-training.jsonl \
  --file-editing-data data/qwen3-file-editing-tools-training.jsonl \
  --output data/qwen3-combined-tool-training.jsonl

# Train on combined data
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-combined-tool-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-combined-training
```

However, the two-track approach is recommended for better learning outcomes.
