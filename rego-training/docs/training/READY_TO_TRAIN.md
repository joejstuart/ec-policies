# Ready to Train - Checklist

## ✅ Completed

1. **Training Data Scripts Updated**:
   - ✅ System prompts emphasize "generate tool calls and complete file content"
   - ✅ Language clarified: LLM doesn't directly edit files
   - ✅ All examples show complete file content (not diffs)
   - ✅ Workflow steps explicitly stated: read → reason → generate complete content → write

2. **Inference Script Updated**:
   - ✅ Workflow validation added
   - ✅ Warnings for natural language inference
   - ✅ Validation for complete content (not diffs)
   - ✅ System prompts match training data

3. **All Scripts Compile**:
   - ✅ No syntax errors
   - ✅ All imports work

## 📋 Next Steps: Training Workflow

### Step 1: Regenerate Training Data

```bash
cd rego-training

# Generate generic tool usage training (with updated prompts)
python scripts/core/generate_generic_tool_usage_training.py \
    --output data/qwen3-generic-tool-usage-training-v4.jsonl

# Generate file editing training (with updated prompts)
python scripts/core/generate_file_editing_training_with_tools.py \
    --output data/qwen3-file-editing-training-v2.jsonl
```

### Step 2: Merge Training Data

```bash
python scripts/core/merge_training_data.py \
    --rule-data data/qwen3-complete-training.jsonl \
    --generic-tool-data data/qwen3-generic-tool-usage-training-v4.jsonl \
    --file-editing-data data/qwen3-file-editing-training-v2.jsonl \
    --output data/qwen3-complete-with-workflow-v1.jsonl
```

### Step 3: Train the Model

```bash
python scripts/core/finetune_qwen3.py \
    --base-model Qwen/Qwen2.5-0.5B \
    --training-data data/qwen3-complete-with-workflow-v1.jsonl \
    --output-dir ./qwen3-workflow-v1 \
    --max-length 3072 \
    --num-epochs 3
```

### Step 4: Test Inference

```bash
# Test with verbose mode to see validation warnings
python scripts/core/inference_qwen3_with_tools.py \
    --model ./qwen3-workflow-v1 \
    --interactive \
    --mode generic \
    --verbose
```

## 🎯 What to Watch For

### Good Signs:
- ✅ Model generates tool calls consistently
- ✅ Model generates complete file content (not diffs)
- ✅ No workflow validation warnings
- ✅ No natural language inference warnings (or very few)

### Warning Signs:
- ⚠️ Many natural language inference warnings → Model needs more training
- ⚠️ Workflow validation warnings → Model not following read → write pattern
- ⚠️ Content looks like diffs → Model needs better training on complete content

## 📊 Expected Training Data Sizes

After regeneration:
- Generic tool usage: ~570 examples (38 types × 15 each)
- File editing: Variable (depends on available policy files)
- Merged: All combined

## 🚀 You're Ready!

All code changes are complete. You can now:
1. Regenerate training data
2. Merge datasets
3. Train the model
4. Test inference

The training data will teach the model the correct workflow, and the inference script will validate it's being followed.
