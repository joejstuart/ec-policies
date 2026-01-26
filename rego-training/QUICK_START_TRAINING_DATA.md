# Quick Start: Generate and Merge Training Data

## Step-by-Step Commands

### 1. Generate Generic Tool Usage Training

```bash
cd rego-training/scripts/core
python generate_generic_tool_usage_training.py
```

**Output:** `data/qwen3-generic-tool-usage-training.jsonl` (~465 examples)

### 2. Merge with Existing Complete Training

If you already have `qwen3-complete-training.jsonl` (which already contains rule generation + test creation):

```bash
cd rego-training/scripts/core
python merge_training_data.py \
  --rule-data ../../data/qwen3-complete-training.jsonl \
  --generic-tool-data ../../data/qwen3-generic-tool-usage-training.jsonl \
  --test-data "" \
  --output ../../data/qwen3-complete-with-tools.jsonl
```

**Or simpler - just pass the complete file and generic tool data:**

```bash
cd rego-training
python scripts/core/merge_training_data.py \
  --rule-data data/qwen3-complete-training.jsonl \
  --generic-tool-data data/qwen3-generic-tool-usage-training.jsonl \
  --test-data "" \
  --output data/qwen3-complete-with-tools.jsonl
```

**Note:** Use `--test-data ""` to skip loading test data separately, since it's already in the complete training file.

**Or from project root:**

```bash
cd rego-training
python scripts/core/merge_training_data.py \
  --rule-data data/qwen3-complete-training.jsonl \
  --generic-tool-data data/qwen3-generic-tool-usage-training.jsonl \
  --output data/qwen3-complete-with-tools.jsonl
```

**Note:** When running from `scripts/core/`, use `../../data/` to go up two levels to the project root.

### 3. Or Merge All Training Data from Scratch

```bash
cd rego-training/scripts/core

# Generate all training data
python generate_generic_tool_usage_training.py
python generate_training_from_rules.py
python generate_test_creation_training.py
python generate_file_editing_training_with_tools.py

# Merge everything
python merge_training_data.py \
  --generic-tool-data ../data/qwen3-generic-tool-usage-training.jsonl \
  --rule-data ../data/qwen3-training-data.jsonl \
  --test-data ../data/qwen3-test-creation-training.jsonl \
  --file-editing-data ../data/qwen3-file-editing-tools-training.jsonl \
  --output ../data/qwen3-complete-training.jsonl
```

### 4. Verify the Result

```bash
cd rego-training
wc -l data/qwen3-complete-training.jsonl
```

You should see ~1,100+ lines (one example per line).

## What Gets Merged

- **Generic Tool Usage**: ~465 examples (foundational tool skills)
- **Rule Generation**: ~219 examples (domain-specific)
- **Test Creation**: ~432 examples (domain-specific)
- **File Editing**: ~50-200 examples (domain-specific with tools)
- **Total**: ~1,166+ examples

## Next: Fine-tune

```bash
python scripts/core/finetune_qwen3.py \
  --training-data data/qwen3-complete-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-rego-finetuned
```
