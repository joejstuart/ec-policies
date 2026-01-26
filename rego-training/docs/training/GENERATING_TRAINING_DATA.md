# Generating and Merging Training Data

This guide explains how to generate all training data types and combine them into a complete training dataset.

## Quick Start

### Step 1: Generate Generic Tool Usage Training (Track A)

```bash
cd rego-training/scripts/core
python generate_generic_tool_usage_training.py
```

This creates `data/qwen3-generic-tool-usage-training.jsonl` with ~465 examples.

### Step 2: Generate Domain-Specific Training (Track B)

```bash
# Rule generation training
python generate_training_from_rules.py

# Test creation training
python generate_test_creation_training.py

# File editing training (optional, for tool-based model)
python generate_file_editing_training_with_tools.py
```

### Step 3: Merge All Training Data

```bash
python merge_training_data.py \
  --rule-data data/qwen3-training-data.jsonl \
  --test-data data/qwen3-test-creation-training.jsonl \
  --file-editing-data data/qwen3-file-editing-tools-training.jsonl \
  --generic-tool-data data/qwen3-generic-tool-usage-training.jsonl \
  --output data/qwen3-complete-training.jsonl
```

The script will automatically find files in default locations if you don't specify paths.

## Detailed Workflow

### Option 1: Two-Track Training (Recommended)

**Track A: Generic Tool Usage**

```bash
# Generate generic tool usage training
python scripts/core/generate_generic_tool_usage_training.py

# This creates: data/qwen3-generic-tool-usage-training.jsonl
# Contains: ~465 examples of pure tool usage (read/write files)
```

**Track B: Domain-Specific Training**

```bash
# Generate domain-specific training
python scripts/core/generate_training_from_rules.py
python scripts/core/generate_test_creation_training.py
python scripts/core/generate_file_editing_training_with_tools.py

# These create:
# - data/qwen3-training-data.jsonl (rule generation)
# - data/qwen3-test-creation-training.jsonl (test creation)
# - data/qwen3-file-editing-tools-training.jsonl (file editing with tools)
```

**Merge Everything**

```bash
python scripts/core/merge_training_data.py \
  --generic-tool-data data/qwen3-generic-tool-usage-training.jsonl \
  --rule-data data/qwen3-training-data.jsonl \
  --test-data data/qwen3-test-creation-training.jsonl \
  --file-editing-data data/qwen3-file-editing-tools-training.jsonl \
  --output data/qwen3-complete-training.jsonl
```

### Option 2: Merge with Existing Complete Training

If you already have `qwen3-complete-training.jsonl` and want to add generic tool usage:

```bash
# Generate generic tool usage data
python scripts/core/generate_generic_tool_usage_training.py

# Merge with existing complete training
python scripts/core/merge_training_data.py \
  --rule-data data/qwen3-complete-training.jsonl \
  --generic-tool-data data/qwen3-generic-tool-usage-training.jsonl \
  --output data/qwen3-complete-with-tools.jsonl
```

**Note:** When merging with existing complete training, you can pass it as `--rule-data` since the merge script combines all provided files.

### Option 3: Automatic Discovery

The merge script will automatically look for files in default locations:

```bash
# Just run merge - it will find files automatically
python scripts/core/merge_training_data.py \
  --output data/qwen3-complete-training.jsonl
```

It will look for:
- `data/qwen3-training-data.jsonl` (rule generation)
- `data/qwen3-test-creation-training.jsonl` (test creation)
- `data/qwen3-file-editing-training.jsonl` or `data/qwen3-file-editing-tools-training.jsonl` (file editing)
- `data/qwen3-generic-tool-usage-training.jsonl` (generic tool usage)

## Training Data Breakdown

After merging, you'll have:

| Type | Examples | Description |
|------|----------|-------------|
| Generic Tool Usage | ~465 | Pure tool usage (read/write files) |
| Rule Generation | ~219 | Generate Rego rules from requirements |
| Test Creation | ~432 | Create tests for Rego rules |
| File Editing (Tools) | ~50-200 | Edit files using tools |
| **Total** | **~1,166+** | Complete training dataset |

## Verification

After merging, verify the output:

```bash
# Count lines in merged file
wc -l data/qwen3-complete-training.jsonl

# Check a sample
head -n 1 data/qwen3-complete-training.jsonl | python3 -m json.tool
```

## Next Steps

After generating and merging training data:

1. **Validate training data:**
   ```bash
   python scripts/core/validate_training_data.py --data data/qwen3-complete-training.jsonl
   ```

2. **Fine-tune the model:**
   ```bash
   python scripts/core/finetune_qwen3.py \
     --training-data data/qwen3-complete-training.jsonl \
     --model Qwen/Qwen3-1.7B \
     --output-dir ./qwen3-rego-finetuned
   ```

## Troubleshooting

### File Not Found

If a file doesn't exist, the merge script will skip it and continue. Check that you've generated all the data you need:

```bash
ls -lh data/qwen3-*.jsonl
```

### Duplicate Examples

The merge script doesn't deduplicate. If you're merging the same file twice, you'll get duplicates. Make sure each file is only included once.

### File Size

Large training files (1000+ examples) are normal. The complete training file may be several MB.
