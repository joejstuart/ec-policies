# Qwen3 Fine-tuning Guide

This guide explains how to fine-tune a Qwen3 model to generate Rego policy rules from natural language requirements.

## Prerequisites

1. **Python 3.8+** with pip
2. **GPU** (recommended) with CUDA support, or CPU (slower)
3. **HuggingFace account** (for accessing models)

## Installation

1. Install required packages:
```bash
pip install -r requirements-training.txt
```

2. Authenticate with HuggingFace (if using gated models):
```bash
huggingface-cli login
```

## Quick Start

### Basic Fine-tuning

```bash
python finetune_qwen3.py
```

This will:
- Use `Qwen/Qwen2.5-0.5B` as the base model
- Load training data from `data/qwen3-training-data.jsonl`
- Fine-tune for 3 epochs
- Save the model to `./qwen3-rego-finetuned`

### Efficient Fine-tuning with LoRA

LoRA (Low-Rank Adaptation) is recommended for efficient fine-tuning:

```bash
python finetune_qwen3.py --use-lora --lora-r 16 --lora-alpha 32
```

This uses less memory and trains faster while maintaining good performance.

### Custom Configuration

```bash
python finetune_qwen3.py \
    --model Qwen/Qwen2.5-1.5B \
    --output-dir ./my-finetuned-model \
    --epochs 5 \
    --batch-size 8 \
    --learning-rate 1e-4 \
    --use-lora
```

## Command-Line Options

### Model Options
- `--model`: Base model to fine-tune (default: `Qwen/Qwen2.5-0.5B`)
- `--output-dir`: Output directory for fine-tuned model (default: `./qwen3-rego-finetuned`)
- `--training-data`: Path to training data JSONL file (default: `data/qwen3-training-data.jsonl`)

### LoRA Options
- `--use-lora`: Enable LoRA for efficient fine-tuning
- `--lora-r`: LoRA rank (default: 16)
- `--lora-alpha`: LoRA alpha (default: 32)
- `--lora-dropout`: LoRA dropout (default: 0.1)

### Training Options
- `--epochs`: Number of training epochs (default: 3)
- `--batch-size`: Training batch size (default: 4)
- `--gradient-accumulation-steps`: Gradient accumulation steps (default: 4)
- `--learning-rate`: Learning rate (default: 2e-4)
- `--warmup-steps`: Warmup steps (default: 100)
- `--max-length`: Maximum sequence length (default: 2048)
- `--save-steps`: Save checkpoint every N steps (default: 500)
- `--eval-steps`: Evaluate every N steps (default: 500)
- `--logging-steps`: Log every N steps (default: 50)
- `--resume-from-checkpoint`: Resume training from checkpoint
- `--use-fp16`: Use FP16 mixed precision training
- `--use-bf16`: Use BF16 mixed precision training (requires Ampere+ GPU)

## Training Data

The training data is automatically generated from validated Rego rules:
- **File**: `data/qwen3-training-data.jsonl`
- **Format**: JSONL with chat format (system/user/assistant messages)
- **Examples**: 219 validated training examples

To regenerate training data:
```bash
python generate_training_from_rules.py
```

## Model Selection

### Recommended Models

1. **Qwen/Qwen2.5-0.5B** (default)
   - Smallest, fastest to train
   - Good for testing and development
   - ~500M parameters

2. **Qwen/Qwen2.5-1.5B**
   - Better quality, still fast
   - Good balance of size and performance
   - ~1.5B parameters

3. **Qwen/Qwen2.5-3B**
   - Higher quality
   - Requires more GPU memory
   - ~3B parameters

4. **Qwen/Qwen2.5-7B**
   - Best quality
   - Requires significant GPU memory (16GB+)
   - ~7B parameters

## Monitoring Training

### TensorBoard

If TensorBoard is installed, training metrics are automatically logged:
```bash
tensorboard --logdir ./qwen3-rego-finetuned/logs
```

### Checkpoints

Checkpoints are saved every `--save-steps` steps. To resume training:
```bash
python finetune_qwen3.py --resume-from-checkpoint ./qwen3-rego-finetuned/checkpoint-1000
```

## Using the Fine-tuned Model

After fine-tuning, use the model like this:

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

# Load fine-tuned model
model = AutoModelForCausalLM.from_pretrained("./qwen3-rego-finetuned")
tokenizer = AutoTokenizer.from_pretrained("./qwen3-rego-finetuned")

# Prepare input
system_prompt = "You are an expert at writing Rego policy rules..."
user_input = "Verify all tasks have a status of Succeeded."

messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": user_input}
]

# Format and tokenize
text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
inputs = tokenizer(text, return_tensors="pt").to(model.device)

# Generate
outputs = model.generate(**inputs, max_new_tokens=512)
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(response)
```

## Troubleshooting

### Out of Memory (OOM)

1. **Reduce batch size**:
   ```bash
   python finetune_qwen3.py --batch-size 2
   ```

2. **Use LoRA**:
   ```bash
   python finetune_qwen3.py --use-lora
   ```

3. **Use gradient accumulation**:
   ```bash
   python finetune_qwen3.py --batch-size 2 --gradient-accumulation-steps 8
   ```

4. **Use smaller model**:
   ```bash
   python finetune_qwen3.py --model Qwen/Qwen2.5-0.5B
   ```

### Slow Training

1. **Use FP16/BF16**:
   ```bash
   python finetune_qwen3.py --use-fp16  # or --use-bf16 for Ampere+ GPUs
   ```

2. **Increase batch size** (if you have memory):
   ```bash
   python finetune_qwen3.py --batch-size 8
   ```

3. **Use LoRA** (trains faster):
   ```bash
   python finetune_qwen3.py --use-lora
   ```

### Model Not Found

If you get "model not found" errors:
1. Make sure you're authenticated: `huggingface-cli login`
2. Check the model name is correct
3. Some models may require request access on HuggingFace

## Best Practices

1. **Start small**: Begin with `Qwen/Qwen2.5-0.5B` and LoRA to test
2. **Monitor loss**: Watch for overfitting (training loss decreases but eval loss increases)
3. **Save checkpoints**: Use `--save-steps` to save progress regularly
4. **Validate output**: Test the fine-tuned model on new examples
5. **Iterate**: Adjust hyperparameters based on results

## Example Training Session

```bash
# 1. Install dependencies
pip install -r requirements-training.txt

# 2. Authenticate with HuggingFace
huggingface-cli login

# 3. Fine-tune with LoRA (recommended)
python finetune_qwen3.py --use-lora --epochs 5

# 4. Monitor training (in another terminal)
tensorboard --logdir ./qwen3-rego-finetuned/logs

# 5. After training, test the model
python test_finetuned_model.py --model ./qwen3-rego-finetuned
```

## Next Steps

After fine-tuning:
1. Test the model on new policy requirements
2. Evaluate quality and adjust hyperparameters if needed
3. Deploy the model for production use
4. Consider creating an API wrapper for easy integration
