# Next Steps for SBOM Training

## Current Status

✅ **Completed:**
- SBOM structure documentation (`docs/sbom-structure-training-data.md`)
- SBOM training script (`scripts/core/generate_sbom_training_from_rules.py`)
- SBOM directories created (`sbom_data/`, `sbom_rego_rules/`)
- Initial SBOM test cases (`sbom_data/comprehensive_test_cases.json`) - 20 test cases
- All documentation updated to use pure Rego (no library imports)

## Next Steps

### 1. Generate Rego Rules from Test Cases

Create Rego rule files from the test cases:

```bash
cd rego-training
python scripts/core/generate_rego_rules.py \
  --input sbom_data/comprehensive_test_cases.json \
  --output-dir sbom_rego_rules
```

**Note:** You may need to adapt `generate_rego_rules.py` to work with SBOM test cases, or create a SBOM-specific version.

### 2. Generate Validation Tests

Convert comprehensive test cases to validation test format:

```bash
cd rego-training
python scripts/core/generate_validation_tests.py \
  --input sbom_data/comprehensive_test_cases.json \
  --output sbom_data/test_case_definitions.json
```

**Note:** You may need to adapt this script to generate SBOM-specific test data (using SBOM attestation structure instead of SLSA attestation structure).

### 3. Validate Rego Rules

Validate the generated Rego rules against test cases:

```bash
cd rego-training
python scripts/core/validate_all_rules.py \
  --rules-dir sbom_rego_rules \
  --test-definitions sbom_data/test_case_definitions.json
```

### 4. Generate Training Data

Once rules are validated, generate training data:

```bash
cd rego-training/scripts/core
python generate_sbom_training_from_rules.py
```

This will create `sbom_data/qwen3-sbom-training-data.jsonl`.

### 5. Fine-tune Model

Train the model on SBOM training data:

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

## Scripts That May Need Adaptation

The following scripts may need to be adapted or have SBOM-specific versions created:

1. **`generate_rego_rules.py`** - May need to handle SBOM test case format
2. **`generate_validation_tests.py`** - Needs to generate SBOM attestation test data instead of SLSA attestation data
3. **`validate_all_rules.py`** - Should work as-is, but may need SBOM-specific test data structure

## Adding More Test Cases

To add more SBOM test cases, edit `sbom_data/comprehensive_test_cases.json` and add entries following the same format:

```json
{
  "test_cases": {
    "sbom_spdx_XXX": {
      "natural_language": "Your requirement description",
      "rego_code": "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    ...\n}",
      "keys_used": ["input.attestations", "statement.predicateType", "..."],
      "type": "single_key"  // or "compound"
    }
  }
}
```

## Example SBOM Test Data

Use the example SBOM at `rego-training/sbom-example.json` as a reference for creating test data. The test data should follow this structure:

```json
{
  "attestations": [
    {
      "statement": {
        "predicateType": "https://spdx.dev/Document",
        "predicate": {
          "SPDXID": "SPDXRef-DOCUMENT",
          "packages": [...],
          "files": [...]
        }
      }
    }
  ]
}
```

## Quick Reference

**Current test cases cover:**
- SPDX: packages, files, SPDXID, name, creation info, package properties (name, version, supplier, license, external refs)
- CycloneDX: components, bomFormat, component properties (name, type, version)

**Areas to expand:**
- More complex package validation (PURL patterns, version ranges)
- File validation
- Relationship validation
- License validation
- More CycloneDX fields (metadata, dependencies)
