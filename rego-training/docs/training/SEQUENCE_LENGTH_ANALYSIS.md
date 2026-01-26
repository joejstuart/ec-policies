# Sequence Length Analysis

## Training Data Analysis

Based on analysis of `qwen3-complete-training.jsonl`:

### By Example Type

1. **Rule Generation** (219 examples - 34%):
   - Average: ~531 tokens
   - Max: ~596 tokens
   - ✅ **1024 tokens is sufficient** for these

2. **Rule-to-Test** (211 examples - 32%):
   - Average: ~1844 tokens
   - Max: ~2262 tokens
   - ❌ **1024 tokens is NOT sufficient** - 100% would be truncated
   - ✅ **2048 tokens works** for most, but some would still be truncated
   - ✅ **3072 tokens recommended** to avoid truncation

3. **Requirement-to-Rule-and-Test** (221 examples - 34%):
   - Average: ~2165 tokens
   - Max: ~2631 tokens
   - ❌ **1024 tokens is NOT sufficient** - 100% would be truncated
   - ❌ **2048 tokens is marginal** - some would still be truncated
   - ✅ **3072 tokens recommended** to handle all examples

### Overall Statistics

- **Total examples**: 651
- **Average length**: ~5290 characters (~1511 tokens)
- **Median length**: ~5807 characters (~1659 tokens)
- **Max length**: ~9208 characters (~2631 tokens)

### Distribution

- **Over 1024 tokens**: ~65% of examples
- **Over 2048 tokens**: ~40% of examples
- **Over 3072 tokens**: 0% of examples

## Recommendation

**Use 3072 tokens** as the default sequence length:

- ✅ Handles all examples without truncation
- ✅ Covers the longest examples (requirement-to-rule-and-test)
- ✅ Allows test files with full attestation data structures
- ⚠️ Uses more memory, but necessary for quality training

### Memory Impact

- **1024 tokens**: ~8-12 GB GPU memory
- **2048 tokens**: ~12-16 GB GPU memory  
- **3072 tokens**: ~16-20 GB GPU memory

For a 22GB GPU, 3072 tokens should still fit with:
- Batch size: 4
- Gradient accumulation: 4
- LoRA enabled
- FP16 enabled
- Gradient checkpointing enabled

### Alternative: Truncate Long Examples

If memory is tight, you could:
1. Use 2048 tokens and accept some truncation (~40% of examples)
2. Filter out the longest examples
3. Use a smaller batch size (2) with more gradient accumulation (8)

But **3072 is recommended** for best training quality.
