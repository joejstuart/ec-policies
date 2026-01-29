# Quick Start: SBOM Training Data Generation

## Step-by-Step Commands

### 1. Generate SBOM Training Data

```bash
cd rego-training/scripts/core
python generate_sbom_training_from_rules.py
```

**Output:** `sbom_data/qwen3-sbom-training-data.jsonl`

**Note:** This requires SBOM Rego rules to exist in `sbom_rego_rules/` directory. If you don't have SBOM rules yet, you'll need to:
1. Create test cases in `sbom_data/comprehensive_test_cases.json`
2. Generate Rego rules from test cases
3. Validate the rules
4. Then run the training data generation

### 2. Merge SBOM Training with Other Training Data (Optional)

If you want to combine SBOM training with attestation training:

```bash
cd rego-training/scripts/core
python merge_training_data.py \
  --rule-data ../../data/qwen3-training-data.jsonl \
  --sbom-data ../../sbom_data/qwen3-sbom-training-data.jsonl \
  --test-data ../../data/qwen3-test-creation-training.jsonl \
  --output ../../data/qwen3-complete-with-sbom.jsonl
```

**Or keep them separate:**

```bash
# Just use SBOM training data
python scripts/core/finetune_qwen3.py \
  --training-data sbom_data/qwen3-sbom-training-data.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-sbom-finetuned
```

### 3. Fine-tune Model on SBOM Data

```bash
cd rego-training
python scripts/core/finetune_qwen3.py \
  --training-data sbom_data/qwen3-sbom-training-data.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-sbom-finetuned \
  --use-lora \
  --use-fp16 \
  --epochs 5 \
  --batch-size 4
```

## Directory Structure

```
rego-training/
├── sbom_data/                          # SBOM-specific data
│   ├── test_case_definitions.json     # SBOM test cases
│   └── qwen3-sbom-training-data.jsonl # SBOM training output
├── sbom_rego_rules/                    # SBOM Rego rules
│   └── *.rego                         # SBOM policy files
├── data/                               # Attestation training data (separate)
│   └── qwen3-training-data.jsonl      # Attestation training
└── rego_rules/                        # Attestation Rego rules (separate)
    └── *.rego                         # Attestation policy files
```

## Key Differences from Attestation Training

1. **Separate Directories**: SBOM training uses `sbom_data/` and `sbom_rego_rules/` to keep it separate from attestation training
2. **SBOM Structure**: Uses pure Rego to access SBOMs directly from `input.attestations` by checking `predicateType` (no library imports)
3. **System Prompts**: Training examples include SBOM-specific structure documentation
4. **Test Data**: Uses SBOM example data (see `sbom-example.json`)

## Next Steps

1. **Create SBOM Test Cases**: Define requirements and test cases in `sbom_data/comprehensive_test_cases.json`
2. **Generate Rego Rules**: Create Rego files in `sbom_rego_rules/` from test cases
3. **Validate Rules**: Ensure all rules pass validation
4. **Generate Training Data**: Run `generate_sbom_training_from_rules.py`
5. **Fine-tune Model**: Train on SBOM training data

## Documentation

- **SBOM Structure**: See `docs/sbom-structure-training-data.md` for complete SBOM path mappings
- **SBOM Training Process**: See `docs/SBOM_TRAINING_PROCESS.md` for detailed workflow
- **Attestation Training**: See `docs/COMPLETE_PROCESS.md` for comparison
