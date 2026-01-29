# SBOM Training Setup

This document summarizes the SBOM training setup, which is kept separate from the SLSA attestation training to allow independent reproduction of both training processes.

## Overview

The SBOM training process follows the same workflow as attestation training but uses SBOM-specific:
- Data directories (`sbom_data/`, `sbom_rego_rules/`)
- Training scripts (`generate_sbom_training_from_rules.py`)
- Structure documentation (`docs/sbom-structure-training-data.md`)
- System prompts (SBOM-specific structure in training examples)

## Directory Structure

```
rego-training/
├── sbom_data/                          # SBOM-specific data files
│   ├── test_case_definitions.json     # SBOM test case definitions
│   ├── comprehensive_test_cases.json  # SBOM comprehensive test cases
│   └── qwen3-sbom-training-data.jsonl # SBOM training data output
├── sbom_rego_rules/                    # SBOM-specific Rego rule files
│   └── *.rego                         # Individual SBOM policy rules
├── data/                               # Attestation training data (separate)
│   └── qwen3-training-data.jsonl      # Attestation training output
├── rego_rules/                         # Attestation Rego rules (separate)
│   └── *.rego                         # Attestation policy files
└── docs/
    ├── sbom-structure-training-data.md # SBOM structure documentation
    ├── SBOM_TRAINING_PROCESS.md        # SBOM training workflow
    └── attestation-structure-training-data.md # Attestation structure (for comparison)
```

## Key Files Created

1. **`docs/sbom-structure-training-data.md`** - Complete SBOM structure documentation with path mappings
2. **`docs/SBOM_TRAINING_PROCESS.md`** - Detailed SBOM training workflow
3. **`QUICK_START_SBOM_TRAINING.md`** - Quick reference for SBOM training
4. **`scripts/core/generate_sbom_training_from_rules.py`** - SBOM training data generator
5. **Updated `scripts/core/merge_training_data.py`** - Now supports `--sbom-data` parameter

## Quick Start

### Generate SBOM Training Data

```bash
cd rego-training/scripts/core
python generate_sbom_training_from_rules.py
```

**Output:** `sbom_data/qwen3-sbom-training-data.jsonl`

### Fine-tune Model on SBOM Data

```bash
cd rego-training
python scripts/core/finetune_qwen3.py \
  --training-data sbom_data/qwen3-sbom-training-data.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-sbom-finetuned
```

### Merge SBOM with Attestation Training (Optional)

```bash
cd rego-training/scripts/core
python merge_training_data.py \
  --rule-data ../../data/qwen3-training-data.jsonl \
  --sbom-data ../../sbom_data/qwen3-sbom-training-data.jsonl \
  --test-data ../../data/qwen3-test-creation-training.jsonl \
  --output ../../data/qwen3-complete-with-sbom.jsonl
```

## Key Differences from Attestation Training

1. **SBOM Access**: Uses pure Rego to access SBOMs directly from `input.attestations` by checking `predicateType` (no library imports)
2. **Structure**: SBOMs have packages, files, external references (PURL, CPE), etc.
3. **System Prompts**: Training examples include SBOM-specific structure documentation
4. **Separate Directories**: All SBOM files are isolated in `sbom_data/` and `sbom_rego_rules/`

## Example SBOM

An example SPDX SBOM is available at `rego-training/sbom-example.json` for reference.

## Documentation

- **SBOM Structure**: `docs/sbom-structure-training-data.md` - Complete path mappings
- **SBOM Training Process**: `docs/SBOM_TRAINING_PROCESS.md` - Detailed workflow
- **Quick Start**: `QUICK_START_SBOM_TRAINING.md` - Quick reference
- **Attestation Training**: `docs/COMPLETE_PROCESS.md` - For comparison

## Next Steps

1. Create SBOM test cases in `sbom_data/comprehensive_test_cases.json`
2. Generate Rego rules in `sbom_rego_rules/` from test cases
3. Validate rules
4. Generate training data using `generate_sbom_training_from_rules.py`
5. Fine-tune model on SBOM training data

## Reproducibility

Both training processes (attestation and SBOM) are now completely separated:
- Separate data directories
- Separate Rego rule directories
- Separate training scripts
- Separate documentation

This allows you to:
- Reproduce attestation training independently
- Reproduce SBOM training independently
- Combine both if desired using the merge script
