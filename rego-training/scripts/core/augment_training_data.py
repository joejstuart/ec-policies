#!/usr/bin/env python3
"""
Augment training data with instruction variations.

This script merges original training data with variations, deduplicates,
and creates the final augmented dataset.

Usage:
    python augment_training_data.py \
      --original data/qwen3-complete-training.jsonl \
      --variations data/qwen3-variations.jsonl \
      --output data/qwen3-augmented-training.jsonl
"""

import argparse
import json
import random
from pathlib import Path
from typing import Dict, List, Set


def normalize_instruction(instruction: str) -> str:
    """Normalize instruction for deduplication."""
    return instruction.lower().strip()


def load_examples(file_path: Path) -> List[Dict]:
    """Load examples from JSONL file."""
    examples = []
    with open(file_path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def deduplicate_examples(examples: List[Dict]) -> List[Dict]:
    """Remove duplicate examples based on user instruction."""
    seen = set()
    unique_examples = []
    
    for ex in examples:
        instruction = normalize_instruction(ex["messages"][1]["content"])
        if instruction not in seen:
            seen.add(instruction)
            unique_examples.append(ex)
    
    return unique_examples


def main():
    parser = argparse.ArgumentParser(
        description="Augment training data with instruction variations"
    )
    parser.add_argument(
        "--original",
        type=str,
        default="data/qwen3-complete-training.jsonl",
        help="Original training data file"
    )
    parser.add_argument(
        "--variations",
        type=str,
        default="data/qwen3-variations.jsonl",
        help="Variations data file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/qwen3-augmented-training.jsonl",
        help="Output augmented training data file"
    )
    parser.add_argument(
        "--shuffle",
        action="store_true",
        default=True,
        help="Shuffle examples (default: True)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for shuffling (default: 42)"
    )
    
    args = parser.parse_args()
    
    # Load original data
    original_path = Path(args.original)
    if not original_path.exists():
        print(f"❌ Error: Original file not found: {original_path}")
        return 1
    
    print(f"📖 Loading original data from {original_path}")
    original_examples = load_examples(original_path)
    print(f"   Loaded {len(original_examples)} examples")
    
    # Load variations
    variations_path = Path(args.variations)
    if not variations_path.exists():
        print(f"⚠️  Variations file not found: {variations_path}")
        print(f"   Run generate_instruction_variations.py first")
        all_examples = original_examples
    else:
        print(f"📖 Loading variations from {variations_path}")
        variation_examples = load_examples(variations_path)
        print(f"   Loaded {len(variation_examples)} examples")
        
        # Merge
        print(f"\n🔄 Merging datasets...")
        all_examples = original_examples + variation_examples
        print(f"   Total before deduplication: {len(all_examples)}")
        
        # Deduplicate
        print(f"🔄 Deduplicating...")
        all_examples = deduplicate_examples(all_examples)
        print(f"   Total after deduplication: {len(all_examples)}")
        print(f"   Removed {len(original_examples) + len(variation_examples) - len(all_examples)} duplicates")
    
    # Shuffle
    if args.shuffle:
        print(f"🔄 Shuffling (seed={args.seed})...")
        random.seed(args.seed)
        random.shuffle(all_examples)
    
    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"\n💾 Saving to {output_path}")
    with open(output_path, 'w') as f:
        for example in all_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"✅ Saved {len(all_examples)} examples to {output_path}")
    
    # Statistics
    print(f"\n📊 Final Statistics:")
    print(f"   Original examples: {len(original_examples)}")
    if variations_path.exists():
        print(f"   Variation examples: {len(variation_examples)}")
        print(f"   New variations: {len(all_examples) - len(original_examples)}")
    print(f"   Total examples: {len(all_examples)}")
    print(f"   Increase: {len(all_examples) / len(original_examples):.1f}x")
    
    return 0


if __name__ == "__main__":
    exit(main())
