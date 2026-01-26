# Rego Policy Training System

This directory contains scripts and tools for fine-tuning Qwen3 models to generate Rego policy rules from natural language requirements.

## Directory Structure

```
rego-training/
├── README.md                    # This file
├── *.py                         # Training and validation scripts
├── data/                        # Training data and test cases
│   ├── *.jsonl                 # Training datasets
│   └── *.json                  # Test case definitions
├── docs/                        # Documentation
│   ├── training/               # Training guides
│   ├── deployment/             # Deployment guides
│   └── troubleshooting/        # Troubleshooting guides
└── rego_rules/                 # Rego rule files
```

## Quick Start

### Fine-tune a Model

```bash
# See docs/training/QUICK_START.md for full guide
python finetune_qwen3.py \
  --training-data data/qwen3-complete-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --use-lora
```

### Generate Instruction Variations

```bash
# Generate variations for training data augmentation
python generate_instruction_variations.py \
  --input data/qwen3-complete-training.jsonl \
  --output data/qwen3-variations.jsonl
```

### Run Inference

```bash
# Use fine-tuned model to generate Rego rules
python inference_qwen3.py \
  --model ./qwen3-rego-finetuned \
  --mode rule \
  --prompt "Verify all tasks have status 'Succeeded'."
```

## Scripts

Scripts are organized in the `scripts/` directory:

- **`scripts/core/`** - Core workflow scripts (test generation, validation, training data, fine-tuning)
- **`scripts/deployment/`** - Deployment scripts (Ollama, GGUF conversion)
- **`scripts/utilities/`** - Utility scripts (optional helpers)
- **`scripts/obsolete/`** - Obsolete scripts (kept for reference)

See [`scripts/README.md`](scripts/README.md) for complete script documentation.

### Quick Reference

**Core Workflow:**
- `scripts/core/generate_training_from_rules.py` - Generate training data
- `scripts/core/finetune_qwen3.py` - Fine-tune model
- `scripts/core/inference_qwen3.py` - Run inference

**Deployment:**
- `scripts/deployment/merge_lora_for_ollama.py` - Merge LoRA for Ollama
- `scripts/deployment/create_ollama_modelfile.py` - Create Modelfile

See [`docs/COMPLETE_PROCESS.md`](docs/COMPLETE_PROCESS.md) for the complete workflow.

## Documentation

See `docs/README.md` for complete documentation index.

### Quick Links
- **Getting Started**: [`docs/training/QUICK_START.md`](docs/training/QUICK_START.md)
- **Fine-tuning Guide**: [`docs/training/FINETUNING.md`](docs/training/FINETUNING.md)
- **Instruction Variations**: [`docs/training/VARIATION_TRAINING_WORKFLOW.md`](docs/training/VARIATION_TRAINING_WORKFLOW.md)
- **Ollama Deployment**: [`docs/deployment/OLLAMA_NEXT_STEPS.md`](docs/deployment/OLLAMA_NEXT_STEPS.md)
- **Troubleshooting**: [`docs/troubleshooting/`](docs/troubleshooting/)

## Training Data

Training datasets are stored in `data/`:
- **`qwen3-complete-training.jsonl`** - Complete training dataset (rule generation + test creation)
- **`qwen3-training-data.jsonl`** - Original rule generation dataset
- **`qwen3-test-creation-training.jsonl`** - Test creation training dataset
- **`test_case_definitions.json`** - Test case definitions for validation

## Requirements

- Python 3.8+
- PyTorch (with CUDA for GPU training)
- Transformers, Datasets, PEFT libraries
- OPA (Open Policy Agent) for validation

See [`docs/troubleshooting/INSTALLATION.md`](docs/troubleshooting/INSTALLATION.md) for installation instructions.

## Workflow

1. **Generate Training Data**: Use scripts to generate training examples from Rego rules
2. **Augment with Variations**: Generate instruction variations for robustness
3. **Fine-tune Model**: Train Qwen3 model on the training data
4. **Validate**: Test the fine-tuned model on held-out examples
5. **Deploy**: Export to Ollama or use inference script

See [`docs/training/QUICK_START.md`](docs/training/QUICK_START.md) for detailed workflow.
