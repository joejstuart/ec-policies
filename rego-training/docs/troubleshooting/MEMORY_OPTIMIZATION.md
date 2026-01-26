# Memory Optimization for Training

If you encounter CUDA out of memory errors, try these solutions:

## Quick Fixes

### 1. Reduce Batch Size and Increase Gradient Accumulation

```bash
python finetune_qwen3.py \
  --training-data data/qwen3-complete-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --batch-size 2 \
  --gradient-accumulation-steps 8 \
  --use-lora \
  --use-fp16
```

This maintains the same effective batch size (2 * 8 = 16) but uses less memory.

### 2. Reduce Sequence Length

```bash
python finetune_qwen3.py \
  --training-data data/qwen3-complete-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --max-length 512 \
  --batch-size 4 \
  --use-lora \
  --use-fp16
```

### 3. Use Environment Variable for Memory Fragmentation

```bash
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
python finetune_qwen3.py \
  --training-data data/qwen3-complete-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --use-lora \
  --use-fp16
```

## Default Settings (Updated)

The script now uses more memory-efficient defaults:
- **Batch size**: 4 (reduced from 8)
- **Gradient accumulation**: 4 (increased from 2)
- **Max length**: 1024 (reduced from 2048)
- **Effective batch size**: 16 (4 * 4 = 16, same as before)

## Advanced Options

### Use 8-bit Optimizers (if bitsandbytes is installed)

Uncomment in `requirements-training.txt`:
```
bitsandbytes>=0.41.0
```

Then modify the training script to use 8-bit optimizers.

### Clear GPU Cache

If you're running multiple experiments, clear the cache between runs:
```python
import torch
torch.cuda.empty_cache()
```

## Memory Usage Estimates

For Qwen3-1.7B with LoRA:
- **Batch size 8, max_length 2048**: ~15-20 GB
- **Batch size 4, max_length 1024**: ~8-12 GB
- **Batch size 2, max_length 512**: ~4-6 GB

## Recommended Settings for 22GB GPU

```bash
python finetune_qwen3.py \
  --training-data data/qwen3-complete-training.jsonl \
  --model Qwen/Qwen3-1.7B \
  --batch-size 4 \
  --gradient-accumulation-steps 4 \
  --max-length 1024 \
  --use-lora \
  --use-fp16
```

This should use ~10-12 GB, leaving headroom for other processes.
