# Scripts Directory

This directory contains all Python scripts organized by purpose.

## Organization

### `core/` - Core Workflow Scripts

Essential scripts for the main workflow:

**Phase 1: Test Case Definition**
- `generate_comprehensive_test_cases.py` - Generate comprehensive test cases
- `generate_validation_tests.py` - Generate validation test data

**Phase 2: Rego Rule Generation**
- `generate_rego_rules.py` - Generate Rego rule files

**Phase 3: Validation**
- `validate_all_rules.py` - Validate all Rego rules

**Phase 4: Training Data Generation**
- `generate_training_from_rules.py` - Generate rule generation training data
- `generate_test_creation_training.py` - Generate test creation training data
- `merge_training_data.py` - Merge training datasets
- `validate_training_data.py` - Validate training data format

**Phase 5: Instruction Variations**
- `generate_instruction_variations.py` - Generate instruction variations
- `validate_variations.py` - Validate variations
- `augment_training_data.py` - Merge variations with original data

**Phase 6: Fine-tuning**
- `finetune_qwen3.py` - Fine-tune Qwen3 model

**Phase 7: Inference**
- `inference_qwen3.py` - Run inference with fine-tuned model

### `deployment/` - Deployment Scripts

Scripts for deploying models to Ollama:

- `merge_lora_for_ollama.py` - Merge LoRA adapters for Ollama
- `create_ollama_modelfile.py` - Generate Ollama Modelfile
- `fix_tokenizer_for_gguf.py` - Fix tokenizer for GGUF conversion

### `utilities/` - Utility Scripts

Optional utility scripts:

- `generate_rego_tests.py` - Generate OPA test files (for manual testing)
- `add_more_test_cases.py` - Add more test cases
- `validate_test_data.py` - Validate test data format

### `obsolete/` - Obsolete Scripts

Scripts that are no longer used (kept for reference):

- `generate_training_data.py` - Replaced by `generate_training_from_rules.py`
- `validate_and_add_training.py` - Replaced by validation workflow

## Core Library

**`validate_rego_training.py`** (in root directory) - Core validation engine used by other scripts. Kept in root for easy imports.

## Usage

Scripts can be run from the `rego-training/` directory:

```bash
# Core workflow
python scripts/core/generate_training_from_rules.py

# Deployment
python scripts/deployment/merge_lora_for_ollama.py

# Utilities
python scripts/utilities/generate_rego_tests.py
```

Or add `scripts/core/`, `scripts/deployment/`, etc. to your PATH.

## See Also

- [`../docs/COMPLETE_PROCESS.md`](../docs/COMPLETE_PROCESS.md) - Complete process documentation
- [`../README.md`](../README.md) - Main README
