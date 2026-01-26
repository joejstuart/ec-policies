#!/usr/bin/env python3
"""
Merge LoRA adapters into base model for Ollama deployment.

This script merges LoRA weights into the base model, creating a single
model file that can be converted to GGUF format for Ollama.

Usage:
    python merge_lora_for_ollama.py --adapter-path ./qwen3-rego-finetuned --output ./qwen3-rego-finetuned-merged
"""

import argparse
import sys
from pathlib import Path

try:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    print("Error: Required libraries not found. Install with: pip install transformers peft torch")
    sys.exit(1)


def merge_lora_model(adapter_path: str, base_model: str, output_path: str):
    """Merge LoRA adapters into base model."""
    adapter_path = Path(adapter_path)
    output_path = Path(output_path)
    
    if not adapter_path.exists():
        print(f"❌ Error: Adapter path does not exist: {adapter_path}")
        return False
    
    print(f"📥 Loading base model: {base_model}")
    try:
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=torch.float16,
            device_map="auto",
            trust_remote_code=True,
        )
        tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=True)
    except Exception as e:
        print(f"❌ Error loading base model: {e}")
        return False
    
    print(f"📥 Loading LoRA adapters from: {adapter_path}")
    try:
        model = PeftModel.from_pretrained(model, str(adapter_path))
    except Exception as e:
        print(f"❌ Error loading LoRA adapters: {e}")
        print("   Note: If you didn't use LoRA, you can skip this step")
        return False
    
    print("🔧 Merging LoRA weights into base model...")
    try:
        model = model.merge_and_unload()
    except Exception as e:
        print(f"❌ Error merging adapters: {e}")
        return False
    
    print(f"💾 Saving merged model to: {output_path}")
    output_path.mkdir(parents=True, exist_ok=True)
    
    try:
        model.save_pretrained(str(output_path))
        tokenizer.save_pretrained(str(output_path))
        print(f"✅ Merged model saved successfully!")
        print(f"   Model: {output_path / 'pytorch_model.bin'}")
        print(f"   Tokenizer: {output_path / 'tokenizer.json'}")
        return True
    except Exception as e:
        print(f"❌ Error saving model: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Merge LoRA adapters into base model for Ollama deployment"
    )
    parser.add_argument(
        "--adapter-path",
        type=str,
        default="./qwen3-rego-finetuned",
        help="Path to fine-tuned model with LoRA adapters (default: ./qwen3-rego-finetuned)"
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="Qwen/Qwen3-1.7B",
        help="Base model name (default: Qwen/Qwen3-1.7B)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./qwen3-rego-finetuned-merged",
        help="Output path for merged model (default: ./qwen3-rego-finetuned-merged)"
    )
    
    args = parser.parse_args()
    
    if not DEPENDENCIES_AVAILABLE:
        return 1
    
    success = merge_lora_model(args.adapter_path, args.base_model, args.output)
    
    if success:
        print("\n✅ Model ready for Ollama conversion!")
        print("\nNext steps:")
        print("  1. Convert to GGUF format using llama.cpp")
        print("  2. Create Modelfile (see OLLAMA_DEPLOYMENT_PLAN.md)")
        print("  3. Run: ollama create qwen3-rego -f Modelfile")
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
