#!/usr/bin/env python3
"""
Fine-tune Qwen3 model on Rego policy generation task.

This script fine-tunes a Qwen3 model to generate Rego policy rules from
natural language policy requirements using the training data in
data/qwen3-training-data.jsonl.

Usage:
    python finetune_qwen3.py [options]

Examples:
    # Basic fine-tuning with default settings
    python finetune_qwen3.py

    # Fine-tune with custom model and output
    python finetune_qwen3.py --model Qwen/Qwen2.5-0.5B --output-dir ./qwen3-rego-finetuned

    # Use LoRA for efficient fine-tuning
    python finetune_qwen3.py --use-lora --lora-r 16 --lora-alpha 32

    # Continue from checkpoint
    python finetune_qwen3.py --resume-from-checkpoint ./checkpoint-1000
"""

import argparse
import json
import os
from pathlib import Path
from typing import Optional

try:
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        TrainingArguments,
        Trainer,
        DataCollatorForLanguageModeling,
    )
    from datasets import load_dataset
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Warning: transformers library not found. Install with: pip install transformers datasets")

try:
    from peft import LoraConfig, get_peft_model, TaskType
    PEFT_AVAILABLE = True
except ImportError:
    PEFT_AVAILABLE = False
    print("Warning: peft library not found. Install with: pip install peft")


def load_training_data(data_file: str) -> list:
    """Load training data from JSONL file."""
    data_path = Path(data_file)
    if not data_path.exists():
        raise FileNotFoundError(f"Training data file not found: {data_file}")
    
    examples = []
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    
    print(f"✅ Loaded {len(examples)} training examples from {data_file}")
    return examples


def format_conversation(messages: list) -> str:
    """Format conversation messages into a single text string for training."""
    formatted = ""
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        
        if role == "system":
            formatted += f"<|im_start|>system\n{content}<|im_end|>\n"
        elif role == "user":
            formatted += f"<|im_start|>user\n{content}<|im_end|>\n"
        elif role == "assistant":
            formatted += f"<|im_start|>assistant\n{content}<|im_end|>\n"
    
    return formatted


def prepare_dataset(examples: list, tokenizer, max_length: int = 2048):
    """Prepare dataset for training."""
    def tokenize_function(batch):
        # When batched=True, batch is a dict with column names as keys
        # The "text" column contains the formatted conversations as a list
        texts = batch["text"]
        
        # Ensure texts is a list of strings
        if not isinstance(texts, list):
            texts = [texts] if isinstance(texts, str) else list(texts)
        
        # Ensure all items are strings
        texts = [str(text) for text in texts]
        
        # Tokenize
        tokenized = tokenizer(
            texts,
            truncation=True,
            max_length=max_length,
            padding=False,
            return_tensors=None,
        )
        
        # For causal LM, labels are the same as input_ids
        tokenized["labels"] = tokenized["input_ids"].copy()
        
        return tokenized
    
    # Convert to HuggingFace dataset format
    # Format all conversations first
    formatted_texts = []
    for ex in examples:
        if "messages" in ex:
            formatted_texts.append(format_conversation(ex["messages"]))
        else:
            # Fallback: if already formatted
            formatted_texts.append(str(ex))
    
    dataset_dict = {"text": formatted_texts}
    
    from datasets import Dataset
    dataset = Dataset.from_dict(dataset_dict)
    
    # Tokenize
    tokenized_dataset = dataset.map(
        tokenize_function,
        batched=True,
        remove_columns=dataset.column_names,
    )
    
    return tokenized_dataset


def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune Qwen3 model on Rego policy generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    # Model arguments
    parser.add_argument(
        "--model",
        type=str,
        default="Qwen/Qwen2.5-1.5B",
        help="Base model to fine-tune (default: Qwen/Qwen2.5-1.5B, use Qwen/Qwen3-1.7B if available)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./qwen3-rego-finetuned",
        help="Output directory for fine-tuned model (default: ./qwen3-rego-finetuned)"
    )
    parser.add_argument(
        "--training-data",
        type=str,
        default="data/qwen3-training-data.jsonl",
        help="Path to training data JSONL file (default: data/qwen3-training-data.jsonl)"
    )
    
    # LoRA arguments
    parser.add_argument(
        "--use-lora",
        action="store_true",
        default=True,
        help="Use LoRA for efficient fine-tuning (default: True)"
    )
    parser.add_argument(
        "--no-lora",
        dest="use_lora",
        action="store_false",
        help="Disable LoRA (use full fine-tuning)"
    )
    parser.add_argument(
        "--lora-r",
        type=int,
        default=16,
        help="LoRA rank (default: 16)"
    )
    parser.add_argument(
        "--lora-alpha",
        type=int,
        default=32,
        help="LoRA alpha (default: 32)"
    )
    parser.add_argument(
        "--lora-dropout",
        type=float,
        default=0.1,
        help="LoRA dropout (default: 0.1)"
    )
    
    # Training arguments
    parser.add_argument(
        "--epochs",
        type=int,
        default=5,
        help="Number of training epochs (default: 5)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="Training batch size (default: 8)"
    )
    parser.add_argument(
        "--gradient-accumulation-steps",
        type=int,
        default=2,
        help="Gradient accumulation steps (default: 2)"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=1e-4,
        help="Learning rate (default: 1e-4)"
    )
    parser.add_argument(
        "--warmup-steps",
        type=int,
        default=100,
        help="Warmup steps (default: 100)"
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=2048,
        help="Maximum sequence length (default: 2048)"
    )
    parser.add_argument(
        "--save-steps",
        type=int,
        default=500,
        help="Save checkpoint every N steps (default: 500)"
    )
    parser.add_argument(
        "--eval-steps",
        type=int,
        default=500,
        help="Evaluate every N steps (default: 500)"
    )
    parser.add_argument(
        "--logging-steps",
        type=int,
        default=50,
        help="Log every N steps (default: 50)"
    )
    parser.add_argument(
        "--resume-from-checkpoint",
        type=str,
        default=None,
        help="Resume training from checkpoint"
    )
    parser.add_argument(
        "--use-fp16",
        action="store_true",
        default=True,
        help="Use FP16 mixed precision training (default: True)"
    )
    parser.add_argument(
        "--no-fp16",
        dest="use_fp16",
        action="store_false",
        help="Disable FP16 (use full precision)"
    )
    parser.add_argument(
        "--use-bf16",
        action="store_true",
        help="Use BF16 mixed precision training (requires Ampere+ GPU, overrides FP16)"
    )
    
    args = parser.parse_args()
    
    if not TRANSFORMERS_AVAILABLE:
        print("❌ Error: transformers library is required. Install with:")
        print("   pip install transformers datasets")
        return 1
    
    if args.use_lora and not PEFT_AVAILABLE:
        print("❌ Error: peft library is required for LoRA. Install with:")
        print("   pip install peft")
        return 1
    
    print("=" * 70)
    print("Qwen3 Rego Policy Fine-tuning")
    print("=" * 70)
    print(f"Model: {args.model}")
    print(f"Training data: {args.training_data}")
    print(f"Output directory: {args.output_dir}")
    print(f"Use LoRA: {args.use_lora}")
    if args.use_lora:
        print(f"  LoRA rank: {args.lora_r}, alpha: {args.lora_alpha}, dropout: {args.lora_dropout}")
    print(f"Epochs: {args.epochs}")
    print(f"Batch size: {args.batch_size} (gradient accumulation: {args.gradient_accumulation_steps})")
    print(f"Effective batch size: {args.batch_size * args.gradient_accumulation_steps}")
    print(f"Learning rate: {args.learning_rate}")
    print(f"Mixed precision: {'BF16' if args.use_bf16 else 'FP16' if args.use_fp16 else 'None'}")
    print("=" * 70)
    
    # Load training data
    try:
        examples = load_training_data(args.training_data)
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        return 1
    
    if len(examples) == 0:
        print("❌ Error: No training examples found")
        return 1
    
    # Load tokenizer and model
    print(f"\n📥 Loading model and tokenizer: {args.model}")
    try:
        tokenizer = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
        
        # Set pad token if not set
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        
        model = AutoModelForCausalLM.from_pretrained(
            args.model,
            trust_remote_code=True,
            torch_dtype="auto",
            device_map="auto",
        )
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        print("\nMake sure you have:")
        print("  1. Installed transformers: pip install transformers")
        print("  2. Authenticated with HuggingFace (if using gated models)")
        print("  3. Have sufficient GPU memory")
        return 1
    
    # Apply LoRA if requested
    if args.use_lora:
        print(f"\n🔧 Applying LoRA (r={args.lora_r}, alpha={args.lora_alpha})")
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=args.lora_r,
            lora_alpha=args.lora_alpha,
            lora_dropout=args.lora_dropout,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        )
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()
    
    # Prepare dataset
    print(f"\n📊 Preparing dataset...")
    try:
        dataset = prepare_dataset(examples, tokenizer, max_length=args.max_length)
        
        # Split into train/eval (90/10)
        split_dataset = dataset.train_test_split(test_size=0.1, seed=42)
        train_dataset = split_dataset["train"]
        eval_dataset = split_dataset["test"]
        
        print(f"   Training examples: {len(train_dataset)}")
        print(f"   Evaluation examples: {len(eval_dataset)}")
    except Exception as e:
        print(f"❌ Error preparing dataset: {e}")
        return 1
    
    # Data collator
    data_collator = DataCollatorForLanguageModeling(
        tokenizer=tokenizer,
        mlm=False,  # Causal LM, not masked LM
    )
    
    # Training arguments
    # Use BF16 if specified, otherwise use FP16 if enabled
    use_bf16 = args.use_bf16
    use_fp16 = args.use_fp16 and not use_bf16
    
    # Calculate total training steps for warmup
    total_steps = len(train_dataset) // (args.batch_size * args.gradient_accumulation_steps) * args.epochs
    warmup_steps = max(args.warmup_steps, int(total_steps * 0.1))  # At least 10% warmup
    
    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        warmup_steps=warmup_steps,
        logging_steps=args.logging_steps,
        save_steps=args.save_steps,
        eval_steps=args.eval_steps,
        evaluation_strategy="steps",
        save_strategy="steps",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        fp16=use_fp16,
        bf16=use_bf16,
        logging_dir=f"{args.output_dir}/logs",
        report_to="tensorboard" if os.path.exists("/usr/bin/tensorboard") else None,
        remove_unused_columns=False,
        dataloader_pin_memory=True,  # Better for GPU
        gradient_checkpointing=True,  # Save memory for larger models
        optim="adamw_torch",  # Use PyTorch optimizer for better GPU performance
        lr_scheduler_type="cosine",  # Cosine learning rate schedule
    )
    
    # Initialize trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        data_collator=data_collator,
    )
    
    # Start training
    print(f"\n🚀 Starting training...")
    print(f"   Total steps: ~{len(train_dataset) // (args.batch_size * args.gradient_accumulation_steps) * args.epochs}")
    print(f"   Checkpoints will be saved to: {args.output_dir}")
    print()
    
    try:
        if args.resume_from_checkpoint:
            trainer.train(resume_from_checkpoint=args.resume_from_checkpoint)
        else:
            trainer.train()
        
        # Save final model
        print(f"\n💾 Saving final model to {args.output_dir}")
        trainer.save_model()
        tokenizer.save_pretrained(args.output_dir)
        
        print("\n✅ Fine-tuning completed successfully!")
        print(f"   Model saved to: {args.output_dir}")
        print(f"\nTo use the fine-tuned model:")
        print(f"   from transformers import AutoModelForCausalLM, AutoTokenizer")
        print(f"   model = AutoModelForCausalLM.from_pretrained('{args.output_dir}')")
        print(f"   tokenizer = AutoTokenizer.from_pretrained('{args.output_dir}')")
        
    except Exception as e:
        print(f"\n❌ Error during training: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
