# Plan: Training Model to Recognize Instruction Variations

## Goal

Make the model robust to different phrasings of the same requirement, so it can generate the same Rego rule from various natural language instructions.

## Current State

The training data has 651 examples with specific instruction phrasings. The model needs to learn that these variations all mean the same thing:
- "Verify all tasks have status 'Succeeded'."
- "Check that every task has a status of 'Succeeded'."
- "Ensure all tasks are marked as 'Succeeded'."
- "All tasks must have status 'Succeeded'."
- "Tasks should have status 'Succeeded'."

## Strategy

### Phase 1: Analyze Current Instructions

1. **Extract instruction patterns** from existing training data
2. **Identify common phrasings** and their frequency
3. **Categorize by instruction type**:
   - Verification/Check commands
   - Requirement statements
   - Conditional checks
   - Existence checks
   - Value comparisons

### Phase 2: Create Variation Templates

Create templates for generating variations:

1. **Action verb variations**:
   - Verify → Check, Ensure, Validate, Confirm, Require
   - Has → Contains, Includes, Possesses
   - Set to → Equals, Is, Matches

2. **Quantifier variations**:
   - All → Every, Each, Any, All of the
   - At least one → One or more, Some

3. **Structure variations**:
   - "Verify X has Y" → "X must have Y", "Y should be present in X"
   - "All X have Y" → "Every X contains Y", "X should all have Y"

4. **Formality variations**:
   - Formal: "Verify that all tasks have status 'Succeeded'."
   - Casual: "Make sure tasks are 'Succeeded'."
   - Technical: "Tasks.status == 'Succeeded' for all tasks."

### Phase 3: Generate Variations

For each existing training example:

1. **Keep original** (already in dataset)
2. **Generate 3-5 variations** using templates
3. **Ensure semantic equivalence** (same Rego rule should be generated)
4. **Validate variations** map to the same rule

### Phase 4: Data Augmentation

1. **Create variation generator script**
2. **Apply to all rule-generation examples** (219 examples)
3. **Optionally apply to requirement-to-rule examples** (10 examples)
4. **Skip rule-to-test examples** (they already have rule provided)

### Phase 5: Quality Assurance

1. **Validate variations**:
   - Same Rego rule should be generated
   - Variations are semantically equivalent
   - No duplicate examples

2. **Test with fine-tuned model**:
   - Run inference on variations
   - Verify output matches expected rule
   - Identify patterns that need more training

### Phase 6: Training

1. **Merge variations** with existing training data
2. **Shuffle** to avoid overfitting to specific phrasings
3. **Fine-tune** on expanded dataset
4. **Evaluate** on held-out variation examples

## Implementation Plan

### Step 1: Create Variation Generator

**Script**: `generate_instruction_variations.py`

**Features**:
- Load existing training data
- Extract user messages (instructions)
- Apply variation templates
- Generate new training examples
- Validate semantic equivalence

**Variation Strategies**:
1. **Synonym replacement** (action verbs, quantifiers)
2. **Sentence restructuring** (active/passive, word order)
3. **Formality adjustment** (formal/casual/technical)
4. **Phrasing alternatives** (different ways to express same requirement)

### Step 2: Validation

**Script**: `validate_variations.py`

**Checks**:
- Variations map to same Rego rule
- No information loss in paraphrasing
- Instructions remain clear and unambiguous

### Step 3: Integration

**Script**: `augment_training_data.py`

**Process**:
1. Load original training data
2. Generate variations for rule-generation examples
3. Merge with original (deduplicate)
4. Shuffle and save

### Step 4: Training

Use existing `finetune_qwen3.py` with augmented dataset.

## Example Variations

### Original
```
"Verify all tasks have status 'Succeeded'."
```

### Variations
```
"Check that every task has a status of 'Succeeded'."
"Ensure all tasks are marked as 'Succeeded'."
"All tasks must have status 'Succeeded'."
"Tasks should have status 'Succeeded'."
"Validate that each task's status is 'Succeeded'."
"Require all tasks to have status 'Succeeded'."
```

All should generate the same Rego rule:
```rego
deny contains result if {
    some attestation in input.attestations
    some task in attestation.statement.predicate.buildConfig.tasks
    task.status != "Succeeded"
    result := sprintf("Task %s does not have status Succeeded", [task.name])
}
```

## Metrics

Track:
- **Variation coverage**: How many different phrasings per requirement
- **Semantic accuracy**: % of variations that generate correct rule
- **Model robustness**: Performance on unseen phrasings
- **Training data size**: Before/after augmentation

## Expected Outcomes

1. **3-5x training data** (from 651 to ~2000-3000 examples)
2. **Better generalization** to new instruction phrasings
3. **More robust model** that handles user's natural language variations
4. **Improved user experience** - users can phrase requirements naturally

## Files to Create

1. `generate_instruction_variations.py` - Main variation generator
2. `variation_templates.py` - Templates and patterns
3. `validate_variations.py` - Validation script
4. `augment_training_data.py` - Integration script
5. `INSTRUCTION_VARIATION_PLAN.md` - This document

## Next Steps

1. ✅ Create plan (this document)
2. ⏳ Analyze current instruction patterns
3. ⏳ Create variation templates
4. ⏳ Build variation generator
5. ⏳ Generate variations
6. ⏳ Validate variations
7. ⏳ Augment training data
8. ⏳ Fine-tune model
9. ⏳ Evaluate on test variations
