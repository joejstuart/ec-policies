# Rego Training Data System

This directory contains the complete system for generating, validating, and managing Rego training data for Qwen3 model fine-tuning.

## Directory Structure

```
rego-training/
├── README.md                          # This file
├── validate_rego_training.py          # Core validation engine
├── validate_and_add_training.py        # Workflow script for validation
├── test_case_definitions.json         # Test case library
├── example_validation_workflow.sh     # Example usage script
├── data/                              # Training data files
│   ├── qwen3-training-data.jsonl     # Main training dataset (JSONL format)
│   └── attestation-training-examples.json  # Structured examples with metadata
└── docs/                              # Documentation
    ├── README_VALIDATION.md           # Validation system usage guide
    ├── VALIDATION_SYSTEM_SUMMARY.md   # System overview
    ├── TRAINING_DATA_SUMMARY.md       # Training data summary
    ├── qwen3-training-review.md       # Training data quality review
    └── attestation-structure-training-data.md  # Attestation structure reference
```

## Quick Start

### Validate a Candidate Rego Example

```bash
cd rego-training
python3 validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego
```

### Validate and Add to Training Data

```bash
python3 validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego \
  --add-if-valid
```

### Validate Entire Training File

```bash
python3 validate_and_add_training.py \
  --validate-file data/qwen3-training-data.jsonl
```

## Components

### Core Scripts

- **`validate_rego_training.py`**: Core validation engine that runs Rego code against test cases using OPA
- **`validate_and_add_training.py`**: Workflow script with CLI interface for validation and adding to training data
- **`test_case_definitions.json`**: Predefined test cases for common natural language patterns

### Training Data

- **`data/qwen3-training-data.jsonl`**: Main training dataset in JSONL format (one example per line)
- **`data/attestation-training-examples.json`**: Structured examples with detailed metadata

### Documentation

See the `docs/` directory for detailed documentation:
- **README_VALIDATION.md**: Complete validation system usage guide
- **VALIDATION_SYSTEM_SUMMARY.md**: System architecture and design
- **TRAINING_DATA_SUMMARY.md**: Training data overview
- **attestation-structure-training-data.md**: Reference for attestation JSON structure

## Workflow

1. **Generate Candidate**: Create Rego code from natural language (manually or via LLM)
2. **Validate**: Run validation script to test against test cases
3. **Fix Issues**: Address any validation errors
4. **Re-validate**: Run again until all tests pass
5. **Add to Training**: Use `--add-if-valid` flag to add to training data

## Requirements

- Python 3.7+
- OPA (Open Policy Agent) installed and in PATH
- Access to `../policy` directory for Rego imports (if needed)

## Example

```bash
# Create a candidate Rego file
cat > candidate.rego << 'EOF'
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildDefinition.tasks
    task.name == "prefetch-dependencies"
    task.invocation.parameters.mode == "permissive"
    result := "prefetch-dependencies mode is permissive"
}
EOF

# Validate it
python3 validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego

# If validation passes, add to training data
python3 validate_and_add_training.py \
  --validate "Verify the prefetch-dependencies task was not invoked with permissive mode" \
  candidate.rego \
  --add-if-valid
```

## Documentation

For detailed information, see:
- [Training Data Generation Plan](docs/TRAINING_DATA_GENERATION_PLAN.md) - **Start here for generating new training data**
- [Validation System Guide](docs/README_VALIDATION.md)
- [System Summary](docs/VALIDATION_SYSTEM_SUMMARY.md)
- [Training Data Summary](docs/TRAINING_DATA_SUMMARY.md)
