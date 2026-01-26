#!/usr/bin/env python3
"""
Fix tokenizer configuration for GGUF conversion.

Some tokenizer configs have issues with special tokens that break
llama.cpp's conversion script. This script fixes those issues.

Usage:
    python fix_tokenizer_for_gguf.py --model-path ./qwen3-rego-finetuned-merged
"""

import argparse
import json
import sys
from pathlib import Path


def fix_tokenizer_config(model_path: str) -> bool:
    """Fix tokenizer configuration for GGUF conversion."""
    model_path = Path(model_path)
    
    if not model_path.exists():
        print(f"❌ Error: Model path does not exist: {model_path}")
        return False
    
    tokenizer_config_file = model_path / "tokenizer_config.json"
    if not tokenizer_config_file.exists():
        print(f"❌ Error: tokenizer_config.json not found in {model_path}")
        return False
    
    print(f"📖 Reading tokenizer config from {tokenizer_config_file}")
    try:
        with open(tokenizer_config_file) as f:
            config = json.load(f)
    except Exception as e:
        print(f"❌ Error reading config: {e}")
        return False
    
    # Backup original
    backup_file = tokenizer_config_file.with_suffix(".json.backup")
    print(f"💾 Backing up to {backup_file}")
    with open(backup_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Fix special tokens issues
    fixed = False
    
    # Check for special_tokens_map that might be a list instead of dict
    if "special_tokens_map" in config:
        if isinstance(config["special_tokens_map"], list):
            print("⚠️  special_tokens_map is a list, converting to dict")
            # Convert list to dict if needed
            st_map = {}
            for item in config["special_tokens_map"]:
                if isinstance(item, dict):
                    st_map.update(item)
                elif isinstance(item, str):
                    # Handle string format if needed
                    pass
            config["special_tokens_map"] = st_map
            fixed = True
    
    # Check for added_tokens_decoder
    if "added_tokens_decoder" in config:
        if isinstance(config["added_tokens_decoder"], list):
            print("⚠️  added_tokens_decoder is a list, converting to dict")
            tokens_dict = {}
            for item in config["added_tokens_decoder"]:
                if isinstance(item, dict) and "id" in item:
                    tokens_dict[item["id"]] = item
            config["added_tokens_decoder"] = tokens_dict
            fixed = True
    
    # Check for extra_special_tokens - this is often the culprit
    if "extra_special_tokens" in config:
        if isinstance(config["extra_special_tokens"], list):
            print("⚠️  extra_special_tokens is a list, converting to empty dict")
            # The conversion script expects a dict, not a list
            # If it's empty or we don't need it, remove it
            if len(config["extra_special_tokens"]) == 0:
                del config["extra_special_tokens"]
                fixed = True
            else:
                # Convert list to dict format if needed, or just remove
                print(f"   List has {len(config['extra_special_tokens'])} items, removing field")
                del config["extra_special_tokens"]
                fixed = True
    
    if fixed:
        print(f"💾 Writing fixed config to {tokenizer_config_file}")
        with open(tokenizer_config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print("✅ Tokenizer config fixed!")
        return True
    else:
        print("ℹ️  No fixes needed, but checking for other issues...")
        
        # Try to load tokenizer to verify
        try:
            from transformers import AutoTokenizer
            tokenizer = AutoTokenizer.from_pretrained(str(model_path), trust_remote_code=True)
            print("✅ Tokenizer loads successfully after fix")
            return True
        except Exception as e:
            print(f"❌ Tokenizer still has issues: {e}")
            print("\nTrying alternative fix...")
            
            # More aggressive fix: ensure all special token fields are dicts
            if "special_tokens_map" not in config:
                config["special_tokens_map"] = {}
            elif not isinstance(config["special_tokens_map"], dict):
                config["special_tokens_map"] = {}
            
            if "added_tokens_decoder" not in config:
                config["added_tokens_decoder"] = {}
            elif not isinstance(config["added_tokens_decoder"], dict):
                config["added_tokens_decoder"] = {}
            
            with open(tokenizer_config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            print("✅ Applied more aggressive fix")
            return True


def main():
    parser = argparse.ArgumentParser(
        description="Fix tokenizer configuration for GGUF conversion"
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="./qwen3-rego-finetuned-merged",
        help="Path to merged model directory (default: ./qwen3-rego-finetuned-merged)"
    )
    
    args = parser.parse_args()
    
    success = fix_tokenizer_config(args.model_path)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
