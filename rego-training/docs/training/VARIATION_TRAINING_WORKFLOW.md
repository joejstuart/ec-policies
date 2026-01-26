# Instruction Variation Training Workflow

## Quick Start

### Step 1: Generate Variations

Generate instruction variations for your training data:

```bash
python generate_instruction_variations.py \
  --input data/qwen3-complete-training.jsonl \
  --output data/qwen3-variations.jsonl \
  --variations-per-example 4 \
  --only-rule-generation
```

This will:
- Load your existing training data
- Generate 4 variations per rule-generation example
- Create new training examples with same Rego code but different instructions
- Save to `data/qwen3-variations.jsonl`

**Expected output**: ~876 new examples (219 rule-gen examples × 4 variations)

### Step 2: Validate Variations

Check that variations are semantically equivalent:

```bash
python validate_variations.py --data data/qwen3-variations.jsonl
```

This verifies:
- Variations map to the same Rego rules
- No duplicate instructions
- Quality of generated variations

### Step 3: Augment Training Data

Merge variations with original data:

```bash
python augment_training_data.py \
  --original data/qwen3-complete-training.jsonl \
  --variations data/qwen3-variations.jsonl \
  --output data/qwen3-augmented-training.jsonl
```

This will:
- Combine original + variations
- Remove duplicates
- Shuffle examples
- Create final augmented dataset

**Expected output**: ~1500-2000 examples (651 original + ~876 variations, minus duplicates)

### Step 4: Fine-tune Model

Train on the augmented dataset:

```bash
python finetune_qwen3.py \
  --training-data data/qwen3-augmented-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --output-dir ./qwen3-rego-finetuned-v2 \
  --use-lora \
  --use-fp16
```

## Variation Strategies

The generator uses multiple strategies:

### 1. Synonym Replacement
- **Action verbs**: Verify → Check, Ensure, Validate
- **Quantifiers**: All → Every, Each
- Preserves quoted strings and special values

### 2. Sentence Restructuring
- "Verify X has Y" → "X must have Y"
- "Verify all X have Y" → "All X must have Y"
- "Verify X is Y" → "X must be Y"

### 3. Formality Variations
- Formal: "Validate that..."
- Casual: "Make sure..."
- Direct: "Require..."

## Example Output

### Original
```
"Verify all tasks have status 'Succeeded'."
```

### Generated Variations
```
"Check all tasks have status 'Succeeded'."
"Ensure all tasks have status 'Succeeded'."
"Validate all tasks have status 'Succeeded'."
"All tasks must have status 'Succeeded'."
```

All map to the same Rego rule, teaching the model that these phrasings are equivalent.

## Quality Checks

After generating variations, verify:

1. **Semantic equivalence**: All variations should generate the same rule
2. **Grammar**: No "every tasks" or "all all" errors
3. **Preserved values**: Quoted strings like 'Succeeded' stay intact
4. **Diversity**: Variations are actually different, not just duplicates

## Expected Results

After training on augmented data:

- **Better generalization**: Model handles new phrasings better
- **More robust**: Works with user's natural language variations
- **Improved UX**: Users don't need to phrase requirements exactly

## Troubleshooting

### Too Many Duplicates

If validation shows many duplicates:
- Adjust variation templates
- Increase `--variations-per-example`
- Check for overly similar instructions

### Variations Don't Generate Same Rule

If variations produce different rules:
- Review variation templates
- Check for information loss in paraphrasing
- Manually review problematic examples

### Model Performance

After fine-tuning:
- Test on held-out variation examples
- Compare performance on original vs. variations
- Iterate on variation strategies if needed
