# Complete Process: From Requirements to Deployed Model

This document outlines the complete end-to-end process for creating, validating, and training a Rego policy generation model.

## Overview

The process transforms natural language policy requirements into a fine-tuned Qwen3 model that can generate Rego code. The journey involves:

1. **Test Case Definition** - Define requirements and test cases
2. **Rego Rule Generation** - Create Rego rules from requirements
3. **Validation** - Validate rules against test cases
4. **Training Data Generation** - Convert validated rules to training data
5. **Model Fine-tuning** - Train Qwen3 model on training data
6. **Deployment** - Deploy model to Ollama or use inference script

---

## Phase 1: Test Case Definition

### Purpose
Define natural language requirements and corresponding test cases that will validate Rego rules.

### Scripts Used
- **`generate_comprehensive_test_cases.py`** - Generate comprehensive test cases from requirements
- **`add_more_test_cases.py`** - Add additional test cases to existing set

### Data Files
- **`data/comprehensive_test_cases.json`** - Comprehensive test cases with natural language, Rego code, and test data
- **`data/test_case_definitions.json`** - Test case definitions with validation tests

### Process

1. **Define Requirements**: Create natural language requirements for policy validation
   - Example: "Verify all tasks have status 'Succeeded'."
   - Example: "Verify the build task has annotation 'tekton.dev/tags' set to 'konflux'."

2. **Generate Test Cases**: Use `generate_comprehensive_test_cases.py` to create test cases
   ```bash
   python generate_comprehensive_test_cases.py
   ```
   This creates:
   - Natural language descriptions
   - Rego code (if available)
   - Test data (positive and negative cases)
   - Keys used in the rule

3. **Generate Validation Tests**: Use `generate_validation_tests.py` to create validation test data
   ```bash
   python scripts/core/generate_validation_tests.py
   ```
   This converts `comprehensive_test_cases.json` to `test_case_definitions.json` format with:
   - Positive tests (should_deny: true) - when condition is violated
   - Negative tests (should_deny: false) - when condition is met
   
   **Note**: Test generation is **automatic** using pattern matching, not AI-generated. The script analyzes natural language and `keys_used` to determine what tests to create. See [`TEST_GENERATION_PROCESS.md`](TEST_GENERATION_PROCESS.md) for details.

### Output
- `data/comprehensive_test_cases.json` - Source test cases
- `data/test_case_definitions.json` - Validation-ready test cases

---

## Phase 2: Rego Rule Generation

### Purpose
Create Rego rule files from test case definitions.

### Scripts Used
- **`generate_rego_rules.py`** - Generate Rego rule files from test cases

### Process

1. **Generate Rego Files**: Extract Rego code from test cases and create `.rego` files
   ```bash
   python generate_rego_rules.py
   ```
   This:
   - Reads `data/test_case_definitions.json` and `data/comprehensive_test_cases.json`
   - Extracts Rego code for each test case
   - Creates Rego files in `rego_rules/` directory
   - Includes METADATA annotations with natural language descriptions

### Output
- `rego_rules/*.rego` - Rego rule files (one per test case)

---

## Phase 3: Validation

### Purpose
Validate Rego rules against test cases to ensure correctness.

### Scripts Used
- **`validate_all_rules.py`** - Validate all Rego rules against test cases
- **`validate_rego_training.py`** - Core validation engine (used by other scripts)

### Process

1. **Validate All Rules**: Run validation on all Rego rules
   ```bash
   python validate_all_rules.py
   ```
   This:
   - Loads each Rego rule from `rego_rules/`
   - Loads corresponding test cases from `data/test_case_definitions.json`
   - Runs OPA tests to verify rules work correctly
   - Reports pass/fail status for each rule

2. **Fix Issues**: Address any validation failures
   - Common issues: duplicate `deny` blocks, incorrect paths, logic errors
   - Fix manually or with helper scripts

### Output
- Validation report showing which rules pass/fail
- Fixed Rego rules in `rego_rules/`

---

## Phase 4: Training Data Generation

### Purpose
Convert validated Rego rules into training data for the Qwen3 model.

### Scripts Used
- **`generate_training_from_rules.py`** - Generate training data from validated Rego rules
- **`generate_test_creation_training.py`** - Generate training data for test creation task
- **`generate_file_editing_training.py`** - Generate training data for editing existing policy files
- **`generate_rego_tests.py`** - Generate OPA test files for Rego rules

### Process

1. **Generate Rule Generation Training Data**: Create training examples for rule generation
   ```bash
   python generate_training_from_rules.py
   ```
   This:
   - Reads all Rego files from `rego_rules/`
   - Extracts natural language from METADATA
   - Extracts Rego code
   - Validates against test cases
   - Creates training examples in Qwen3 chat format
   - Outputs to `data/qwen3-training-data.jsonl`

2. **Generate Test Creation Training Data**: Create training examples for test creation
   ```bash
   python generate_test_creation_training.py
   ```
   This:
   - Reads `data/test_case_definitions.json`
   - Creates two types of examples:
     - Rule-to-Test: Given a Rego rule, create tests
     - Requirement-to-Rule-and-Test: Given a requirement, create both rule and tests
   - Outputs to `data/qwen3-test-creation-training.jsonl`

3. **Generate File Editing Training Data** (Optional): Create training examples for editing existing files
   ```bash
   python generate_file_editing_training.py
   ```
   This:
   - Uses actual policy files with multiple rules from `policy/` directory
   - Creates synthetic multi-rule files from training rego files
   - Generates examples showing how to add new rules to existing files
   - Teaches the model proper file structure and rule placement
   - Outputs to `data/qwen3-file-editing-training.jsonl`

4. **Generate Generic Tool Usage Training Data** (Optional, Track A): Create foundational tool usage examples
   ```bash
   python generate_generic_tool_usage_training.py
   ```
   This:
   - Creates ~465 examples of pure tool usage (read/write files)
   - Teaches procedural correctness without domain knowledge
   - Outputs to `data/qwen3-generic-tool-usage-training.jsonl`

5. **Merge Training Data**: Combine all training datasets
   ```bash
   python merge_training_data.py \
     --rule-data data/qwen3-training-data.jsonl \
     --test-data data/qwen3-test-creation-training.jsonl \
     --file-editing-data data/qwen3-file-editing-training.jsonl \
     --generic-tool-data data/qwen3-generic-tool-usage-training.jsonl \
     --output data/qwen3-complete-training.jsonl
   ```

   Or with automatic file discovery:
   ```bash
   python merge_training_data.py --output data/qwen3-complete-training.jsonl
   ```
   
   The script will automatically find files in default locations.

5. **Validate Training Data**: Ensure training data is correctly formatted
   ```bash
   python validate_training_data.py --data data/qwen3-complete-training.jsonl
   ```

### Output
- `data/qwen3-training-data.jsonl` - Rule generation training data
- `data/qwen3-test-creation-training.jsonl` - Test creation training data
- `data/qwen3-file-editing-training.jsonl` - File editing training data (optional)
- `data/qwen3-generic-tool-usage-training.jsonl` - Generic tool usage training data (optional, Track A)
- `data/qwen3-complete-training.jsonl` - Combined training dataset

---

## Phase 5: Instruction Variation Augmentation

### Purpose
Generate variations of instructions to make the model robust to different phrasings.

### Scripts Used
- **`generate_instruction_variations.py`** - Generate instruction variations
- **`validate_variations.py`** - Validate variation quality
- **`augment_training_data.py`** - Merge variations with original data

### Process

1. **Generate Variations**: Create multiple phrasings of each instruction
   ```bash
   python generate_instruction_variations.py \
     --input data/qwen3-complete-training.jsonl \
     --output data/qwen3-variations.jsonl \
     --variations-per-example 4 \
     --only-rule-generation
   ```
   This creates variations like:
   - "Verify X" → "Check X", "Ensure X", "Validate X"
   - "All tasks" → "Every task", "Each task"

2. **Validate Variations**: Ensure variations are semantically equivalent
   ```bash
   python validate_variations.py --data data/qwen3-variations.jsonl
   ```

3. **Augment Training Data**: Merge variations with original data
   ```bash
   python augment_training_data.py \
     --original data/qwen3-complete-training.jsonl \
     --variations data/qwen3-variations.jsonl \
     --output data/qwen3-augmented-training.jsonl
   ```

### Output
- `data/qwen3-variations.jsonl` - Instruction variations
- `data/qwen3-augmented-training.jsonl` - Augmented training dataset (3-5x larger)

---

## Phase 6: Model Fine-tuning

### Purpose
Train Qwen3 model on the training data to learn Rego code generation.

### Scripts Used
- **`finetune_qwen3.py`** - Fine-tune Qwen3 model with LoRA

### Process

1. **Fine-tune Model**: Train on augmented training data
   ```bash
   python finetune_qwen3.py \
     --training-data data/qwen3-augmented-training.jsonl \
     --model Qwen/Qwen3-1.7B \
     --output-dir ./qwen3-rego-finetuned \
     --use-lora \
     --use-fp16 \
     --epochs 5 \
     --batch-size 4
   ```
   This:
   - Loads training data
   - Configures LoRA for efficient fine-tuning
   - Trains model on GPU
   - Saves checkpoints and final model

### Output
- `qwen3-rego-finetuned/` - Fine-tuned model directory
- Checkpoints saved during training
- Final model ready for inference

---

## Phase 7: Deployment

### Purpose
Deploy fine-tuned model for use (Ollama or direct inference).

### Scripts Used
- **`inference_qwen3.py`** - Run inference with fine-tuned model
- **`merge_lora_for_ollama.py`** - Merge LoRA adapters for Ollama
- **`create_ollama_modelfile.py`** - Generate Ollama Modelfile
- **`fix_tokenizer_for_gguf.py`** - Fix tokenizer for GGUF conversion

### Process

#### Option A: Direct Inference

1. **Run Inference**: Use fine-tuned model directly
   ```bash
   python inference_qwen3.py \
     --model ./qwen3-rego-finetuned \
     --mode rule \
     --prompt "Verify all tasks have status 'Succeeded'."
   ```

#### Option B: Ollama Deployment

1. **Merge LoRA Adapters**: Merge adapters into base model
   ```bash
   python merge_lora_for_ollama.py \
     --base-model Qwen/Qwen3-1.7B \
     --lora-model ./qwen3-rego-finetuned \
     --output-dir ./qwen3-rego-finetuned-merged
   ```

2. **Fix Tokenizer**: Fix tokenizer config for GGUF conversion
   ```bash
   python fix_tokenizer_for_gguf.py \
     --model-dir ./qwen3-rego-finetuned-merged
   ```

3. **Convert to GGUF**: Use llama.cpp to convert to GGUF format
   ```bash
   cd llama.cpp
   python convert_hf_to_gguf.py \
     ../qwen3-rego-finetuned-merged \
     --outfile ../llama.cpp/models/qwen3-ollama \
     --outtype f16
   ```

4. **Create Modelfile**: Generate Ollama Modelfile
   ```bash
   python create_ollama_modelfile.py \
     --gguf-model llama.cpp/models/qwen3-ollama.gguf \
     --output Modelfile
   ```

5. **Import to Ollama**: Create Ollama model
   ```bash
   ollama create qwen3-rego -f Modelfile
   ```

### Output
- Fine-tuned model ready for inference
- Ollama model (if deployed to Ollama)

---

## Script Organization

### Core Workflow Scripts (Essential)

**Phase 1: Test Case Definition**
- `generate_comprehensive_test_cases.py` - Generate test cases
- `generate_validation_tests.py` - Generate validation test data

**Phase 2: Rego Rule Generation**
- `generate_rego_rules.py` - Generate Rego files

**Phase 3: Validation**
- `validate_all_rules.py` - Validate all rules
- `validate_rego_training.py` - Core validation engine

**Phase 4: Training Data Generation**
- `generate_training_from_rules.py` - Generate rule generation training data
- `generate_test_creation_training.py` - Generate test creation training data
- `merge_training_data.py` - Merge training datasets
- `validate_training_data.py` - Validate training data format

**Phase 5: Instruction Variations**
- `generate_instruction_variations.py` - Generate variations
- `validate_variations.py` - Validate variations
- `augment_training_data.py` - Merge variations

**Phase 6: Fine-tuning**
- `finetune_qwen3.py` - Fine-tune model

**Phase 7: Deployment**
- `inference_qwen3.py` - Run inference
- `merge_lora_for_ollama.py` - Merge LoRA for Ollama
- `create_ollama_modelfile.py` - Create Modelfile
- `fix_tokenizer_for_gguf.py` - Fix tokenizer

### Utility Scripts (Optional)

- `generate_rego_tests.py` - Generate OPA test files (for manual testing)
- `add_more_test_cases.py` - Add more test cases
- `validate_test_data.py` - Validate test data format

### Obsolete Scripts (Can be removed)

- `generate_training_data.py` - Replaced by `generate_training_from_rules.py`
- `validate_and_add_training.py` - Replaced by validation workflow
- `tmp/*.py` - Temporary fix scripts (no longer needed)

---

## Quick Reference: Common Workflows

### Starting from Scratch

```bash
# 1. Generate test cases
python generate_comprehensive_test_cases.py

# 2. Generate validation tests
python generate_validation_tests.py

# 3. Generate Rego rules
python generate_rego_rules.py

# 4. Validate rules
python validate_all_rules.py

# 5. Generate training data
python generate_training_from_rules.py
python generate_test_creation_training.py
python merge_training_data.py

# 6. Generate variations (optional)
python generate_instruction_variations.py
python augment_training_data.py

# 7. Fine-tune model
python finetune_qwen3.py --training-data data/qwen3-augmented-training.jsonl

# 8. Run inference
python inference_qwen3.py --model ./qwen3-rego-finetuned
```

### Adding New Rules

```bash
# 1. Add to comprehensive_test_cases.json or test_case_definitions.json
# 2. Generate Rego rules
python generate_rego_rules.py

# 3. Validate
python validate_all_rules.py

# 4. Regenerate training data
python generate_training_from_rules.py
python merge_training_data.py

# 5. Retrain model
python finetune_qwen3.py --training-data data/qwen3-complete-training.jsonl
```

### Updating Training Data

```bash
# 1. Regenerate from rules
python generate_training_from_rules.py

# 2. Regenerate variations
python generate_instruction_variations.py
python augment_training_data.py

# 3. Validate
python validate_training_data.py --data data/qwen3-augmented-training.jsonl

# 4. Retrain
python finetune_qwen3.py --training-data data/qwen3-augmented-training.jsonl
```

---

## Data Flow

```
comprehensive_test_cases.json
    ↓ (generate_validation_tests.py)
test_case_definitions.json
    ↓ (generate_rego_rules.py)
rego_rules/*.rego
    ↓ (validate_all_rules.py)
validated rego_rules/*.rego
    ↓ (generate_training_from_rules.py)
qwen3-training-data.jsonl
    ↓ (generate_test_creation_training.py)
qwen3-test-creation-training.jsonl
    ↓ (merge_training_data.py)
qwen3-complete-training.jsonl
    ↓ (generate_instruction_variations.py)
qwen3-variations.jsonl
    ↓ (augment_training_data.py)
qwen3-augmented-training.jsonl
    ↓ (finetune_qwen3.py)
qwen3-rego-finetuned/
    ↓ (inference_qwen3.py or Ollama deployment)
Deployed Model
```

---

## Key Files

### Input Files
- `data/comprehensive_test_cases.json` - Source test cases
- `data/test_case_definitions.json` - Validation test cases
- `rego_rules/*.rego` - Rego rule files

### Output Files
- `data/qwen3-*.jsonl` - Training datasets
- `qwen3-rego-finetuned/` - Fine-tuned model
- `qwen3-rego-finetuned-merged/` - Merged model (for Ollama)

### Documentation
- `docs/COMPLETE_PROCESS.md` - This document
- `docs/training/QUICK_START.md` - Quick start guide
- `docs/training/FINETUNING.md` - Fine-tuning details
- `docs/deployment/OLLAMA_NEXT_STEPS.md` - Ollama deployment

---

## Troubleshooting

### Validation Failures
- Check Rego syntax with `opa check`
- Verify paths match attestation structure
- Ensure test data matches rule logic

### Training Issues
- See `docs/troubleshooting/MEMORY_OPTIMIZATION.md` for CUDA OOM
- See `docs/troubleshooting/INSTALLATION.md` for dependency issues

### Deployment Issues
- See `docs/troubleshooting/GGUF_CONVERSION_TROUBLESHOOTING.md` for conversion errors
- See `docs/deployment/OLLAMA_NEXT_STEPS.md` for Ollama issues

---

## Next Steps

1. **Review Scripts**: Identify which scripts you actually use
2. **Remove Obsolete**: Delete scripts in `tmp/` and unused utilities
3. **Document Workflow**: Update this document as process evolves
4. **Automate**: Create master script that runs entire workflow
