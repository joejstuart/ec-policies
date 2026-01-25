#!/usr/bin/env python3
"""
Merge different training data files into a single training dataset.

This script combines:
1. Rule generation training (qwen3-training-data.jsonl)
2. Test creation training (qwen3-test-creation-training.jsonl)

Into a single comprehensive training file.
"""

import json
from pathlib import Path
from typing import List, Dict


def load_jsonl(file_path: Path) -> List[Dict]:
    """Load examples from JSONL file."""
    examples = []
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    examples.append(json.loads(line))
    return examples


def main():
    base_training = Path("data/qwen3-training-data.jsonl")
    test_creation_training = Path("data/qwen3-test-creation-training.jsonl")
    merged_output = Path("data/qwen3-complete-training.jsonl")
    
    print("=" * 70)
    print("Merging Training Data")
    print("=" * 70)
    
    # Load base training data (rule generation)
    print(f"\n📖 Loading base training data...")
    base_examples = load_jsonl(base_training)
    print(f"   Found {len(base_examples)} rule generation examples")
    
    # Load test creation training data
    print(f"\n📖 Loading test creation training data...")
    test_examples = load_jsonl(test_creation_training)
    print(f"   Found {len(test_examples)} test creation examples")
    
    # Combine all examples
    all_examples = base_examples + test_examples
    
    # Shuffle for better training (optional but recommended)
    import random
    random.seed(42)
    random.shuffle(all_examples)
    
    # Write merged file
    print(f"\n💾 Writing merged training data...")
    with open(merged_output, 'w', encoding='utf-8') as f:
        for example in all_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"\n✅ Merged training data created:")
    print(f"   Rule generation examples: {len(base_examples)}")
    print(f"   Test creation examples: {len(test_examples)}")
    print(f"   Total examples: {len(all_examples)}")
    print(f"   Output: {merged_output}")
    
    # Show breakdown by type
    rule_to_test = sum(1 for ex in test_examples if "create a complete test file" in ex["messages"][1]["content"].lower())
    requirement_to_rule = len(test_examples) - rule_to_test
    
    print(f"\n📊 Test creation breakdown:")
    print(f"   Rule-to-Test examples: {rule_to_test}")
    print(f"   Requirement-to-Rule-and-Test examples: {requirement_to_rule}")
    
    return 0


if __name__ == "__main__":
    exit(main())
