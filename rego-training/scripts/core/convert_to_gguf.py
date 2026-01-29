#!/usr/bin/env python3
"""
Convert fine-tuned HuggingFace model to GGUF format for llama.cpp.

This script handles:
1. Merging LoRA weights (if LoRA was used)
2. Converting to GGUF format
3. Optional quantization

Usage:
    # Basic conversion
    python convert_to_gguf.py --model ./qwen3-rego-finetuned --output ./qwen3-rego-finetuned.gguf
    
    # With quantization
    python convert_to_gguf.py --model ./qwen3-rego-finetuned --output ./qwen3-rego-finetuned.gguf --quantize q4_0
    
    # Merge LoRA first
    python convert_to_gguf.py --model ./qwen3-rego-finetuned --output ./qwen3-rego-finetuned.gguf --merge-lora
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

def check_llamacpp():
    """Check if llama.cpp is available."""
    # Try to find llama.cpp directory
    possible_paths = [
        Path("../llama.cpp"),
        Path("../../llama.cpp"),
        Path.home() / "llama.cpp",
        Path("/usr/local/llama.cpp"),
    ]
    
    for path in possible_paths:
        if path.exists() and (path / "convert_hf_to_gguf.py").exists():
            return path
    
    return None

def merge_lora_weights(model_path: str, output_path: str):
    """Merge LoRA weights into base model."""
    try:
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
        import torch
    except ImportError:
        print("❌ Error: peft and transformers required for LoRA merging")
        print("   Install with: pip install peft transformers torch")
        return False
    
    print(f"\n🔧 Merging LoRA weights...")
    print(f"   Input: {model_path}")
    print(f"   Output: {output_path}")
    
    try:
        # Check if this is a LoRA model
        if not (Path(model_path) / "adapter_config.json").exists():
            print("   ℹ️  No LoRA adapter found, skipping merge")
            return True
        
        # Load base model (try to detect from adapter config)
        adapter_config = json.load(open(Path(model_path) / "adapter_config.json"))
        base_model_name = adapter_config.get("base_model_name_or_path", "Qwen/Qwen2.5-0.5B")
        
        print(f"   Loading base model: {base_model_name}")
        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            torch_dtype=torch.float16,
            trust_remote_code=True
        )
        
        print(f"   Loading LoRA adapter: {model_path}")
        model = PeftModel.from_pretrained(base_model, model_path)
        
        print(f"   Merging weights...")
        merged_model = model.merge_and_unload()
        
        print(f"   Saving merged model to {output_path}")
        Path(output_path).mkdir(parents=True, exist_ok=True)
        merged_model.save_pretrained(output_path)
        
        # Copy tokenizer
        tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        tokenizer.save_pretrained(output_path)
        
        print("   ✅ LoRA weights merged successfully")
        return True
        
    except Exception as e:
        print(f"   ❌ Error merging LoRA: {e}")
        import traceback
        traceback.print_exc()
        return False

def fix_tokenizer_config(model_path: str):
    """Fix tokenizer config for GGUF conversion."""
    tokenizer_config_path = Path(model_path) / "tokenizer_config.json"
    
    if not tokenizer_config_path.exists():
        return True
    
    try:
        with open(tokenizer_config_path, 'r') as f:
            config = json.load(f)
        
        # Remove problematic extra_special_tokens if it's a list
        if 'extra_special_tokens' in config and isinstance(config['extra_special_tokens'], list):
            print(f"   🔧 Fixing tokenizer config (removing extra_special_tokens list)")
            # Backup
            backup_path = tokenizer_config_path.with_suffix('.json.backup')
            shutil.copy(tokenizer_config_path, backup_path)
            
            # Remove
            del config['extra_special_tokens']
            
            # Save
            with open(tokenizer_config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"   ✅ Tokenizer config fixed (backup: {backup_path})")
        
        return True
    except Exception as e:
        print(f"   ⚠️  Warning: Could not fix tokenizer config: {e}")
        return True  # Continue anyway

def convert_to_gguf(model_path: str, output_path: str, quantize: str = None):
    """Convert HuggingFace model to GGUF format."""
    llama_cpp_path = check_llamacpp()
    
    if not llama_cpp_path:
        print("❌ Error: llama.cpp not found")
        print("\nPlease either:")
        print("  1. Clone llama.cpp: git clone https://github.com/ggerganov/llama.cpp.git")
        print("  2. Place it in ../llama.cpp relative to this script")
        print("  3. Or install llama-cpp-python: pip install llama-cpp-python[convert]")
        return False
    
    convert_script = llama_cpp_path / "convert_hf_to_gguf.py"
    
    if not convert_script.exists():
        print(f"❌ Error: convert_hf_to_gguf.py not found at {convert_script}")
        return False
    
    print(f"\n🔄 Converting to GGUF format...")
    print(f"   Model: {model_path}")
    print(f"   Output: {output_path}")
    
    # Fix tokenizer config first
    fix_tokenizer_config(model_path)
    
    # Run conversion
    try:
        cmd = [
            sys.executable,
            str(convert_script),
            model_path,
            "--outfile", str(output_path),
            "--outtype", quantize or "f16"
        ]
        
        print(f"   Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("   ✅ Conversion successful")
        
        # If quantization requested and we got f16, quantize it
        if quantize and quantize != "f16":
            print(f"\n📦 Quantizing to {quantize}...")
            quantize_bin = llama_cpp_path / "quantize"
            if not quantize_bin.exists():
                print(f"   ⚠️  quantize binary not found, skipping quantization")
                print(f"   Build llama.cpp first: cd {llama_cpp_path} && make")
            else:
                f16_path = output_path.with_suffix('.f16.gguf') if not output_path.endswith('.gguf') else output_path
                q_path = output_path if output_path.endswith('.gguf') else output_path.with_suffix('.gguf')
                
                cmd = [str(quantize_bin), str(f16_path), str(q_path), quantize]
                print(f"   Running: {' '.join(cmd)}")
                subprocess.run(cmd, check=True)
                print(f"   ✅ Quantization successful: {q_path}")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Conversion failed: {e}")
        if e.stderr:
            print(f"   Error output: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"   ❌ Error: llama.cpp conversion script not found")
        print(f"   Make sure llama.cpp is installed and convert_hf_to_gguf.py exists")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Convert fine-tuned HuggingFace model to GGUF format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to fine-tuned HuggingFace model"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output GGUF file path"
    )
    
    parser.add_argument(
        "--merge-lora",
        action="store_true",
        help="Merge LoRA weights before conversion (if LoRA was used)"
    )
    
    parser.add_argument(
        "--quantize",
        type=str,
        choices=["q4_0", "q4_1", "q5_0", "q5_1", "q8_0", "f16"],
        default="f16",
        help="Quantization type (default: f16, no quantization)"
    )
    
    args = parser.parse_args()
    
    model_path = Path(args.model)
    output_path = Path(args.output)
    
    if not model_path.exists():
        print(f"❌ Error: Model path does not exist: {model_path}")
        return 1
    
    # Step 1: Merge LoRA if requested
    if args.merge_lora:
        merged_path = model_path.parent / f"{model_path.name}-merged"
        if not merge_lora_weights(str(model_path), str(merged_path)):
            return 1
        model_path = merged_path
    
    # Step 2: Convert to GGUF
    if not convert_to_gguf(str(model_path), str(output_path), args.quantize):
        return 1
    
    print(f"\n✅ Conversion complete!")
    print(f"   GGUF model: {output_path}")
    print(f"\nTo use with llama.cpp:")
    print(f"   ./llama.cpp/main -m {output_path} -p 'Your prompt'")
    print(f"\nOr with Python:")
    print(f"   from llama_cpp import Llama")
    print(f"   llm = Llama(model_path='{output_path}')")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
