#!/usr/bin/env python3
"""
Create separate training datasets for two-model approach:
1. Rule generation only (code generation)
2. File operations only (tool usage)
"""

import argparse
import json
from pathlib import Path
from typing import List, Dict

from merge_training_data import load_jsonl


def main():
    parser = argparse.ArgumentParser(
        description="Create separate training datasets for specialized models"
    )
    parser.add_argument(
        "--rule-data",
        type=str,
        default="data/qwen3-training-data.jsonl",
        help="Path to rule generation training data"
    )
    parser.add_argument(
        "--test-data",
        type=str,
        default="data/qwen3-test-creation-training.jsonl",
        help="Path to test creation training data"
    )
    parser.add_argument(
        "--generic-tool-data",
        type=str,
        default="data/qwen3-generic-tool-usage-training.jsonl",
        help="Path to generic tool usage training data"
    )
    parser.add_argument(
        "--file-editing-data",
        type=str,
        default=None,
        help="Path to file editing training data"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data",
        help="Output directory for separated datasets"
    )
    
    args = parser.parse_args()
    
    # Get script directory and project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent
    
    def resolve_path(path_str):
        if path_str is None:
            return None
        path = Path(path_str)
        if path.is_absolute():
            return path
        if path_str.startswith("../"):
            import os
            cwd = Path(os.getcwd())
            cwd_resolved = (cwd / path_str).resolve()
            try:
                rel_path = cwd_resolved.relative_to(project_root)
                return project_root / rel_path
            except ValueError:
                return cwd_resolved
        return project_root / path
    
    args.rule_data = resolve_path(args.rule_data)
    args.test_data = resolve_path(args.test_data)
    args.generic_tool_data = resolve_path(args.generic_tool_data) if args.generic_tool_data else None
    args.file_editing_data = resolve_path(args.file_editing_data) if args.file_editing_data else None
    args.output_dir = resolve_path(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 70)
    print("Creating Separate Training Datasets")
    print("=" * 70)
    
    # Load all data
    print("\n📖 Loading training data...")
    rule_examples = load_jsonl(args.rule_data)
    print(f"   Rule generation: {len(rule_examples)} examples")
    
    test_examples = load_jsonl(args.test_data)
    print(f"   Test creation: {len(test_examples)} examples")
    
    generic_tool_examples = []
    if args.generic_tool_data:
        generic_tool_examples = load_jsonl(args.generic_tool_data)
        print(f"   Generic tool usage: {len(generic_tool_examples)} examples")
    else:
        # Try default
        default_generic = project_root / "data/qwen3-generic-tool-usage-training.jsonl"
        if default_generic.exists():
            generic_tool_examples = load_jsonl(default_generic)
            print(f"   Generic tool usage: {len(generic_tool_examples)} examples (from default)")
    
    file_editing_examples = []
    if args.file_editing_data:
        file_editing_examples = load_jsonl(args.file_editing_data)
        print(f"   File editing: {len(file_editing_examples)} examples")
    else:
        # Try defaults
        for default_path in [
            project_root / "data/qwen3-file-editing-tools-training.jsonl",
            project_root / "data/qwen3-file-editing-training.jsonl"
        ]:
            if default_path.exists():
                file_editing_examples = load_jsonl(default_path)
                print(f"   File editing: {len(file_editing_examples)} examples (from {default_path.name})")
                break
    
    # Create Rule Generation Only dataset
    print("\n📝 Creating rule generation dataset...")
    rule_gen_examples = rule_examples + test_examples
    
    import random
    random.seed(42)
    random.shuffle(rule_gen_examples)
    
    rule_gen_output = args.output_dir / "qwen3-rule-generation-only.jsonl"
    with open(rule_gen_output, 'w', encoding='utf-8') as f:
        for example in rule_gen_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"   ✅ Created: {rule_gen_output}")
    print(f"   Examples: {len(rule_gen_examples)}")
    
    # Create File Operations Only dataset
    print("\n📝 Creating file operations dataset...")
    file_ops_examples = generic_tool_examples + file_editing_examples
    
    random.seed(42)
    random.shuffle(file_ops_examples)
    
    file_ops_output = args.output_dir / "qwen3-file-operations-only.jsonl"
    with open(file_ops_output, 'w', encoding='utf-8') as f:
        for example in file_ops_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"   ✅ Created: {file_ops_output}")
    print(f"   Examples: {len(file_ops_examples)}")
    
    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"\nRule Generation Dataset:")
    print(f"   File: {rule_gen_output}")
    print(f"   Examples: {len(rule_gen_examples)}")
    print(f"   - Rule generation: {len(rule_examples)}")
    print(f"   - Test creation: {len(test_examples)}")
    
    print(f"\nFile Operations Dataset:")
    print(f"   File: {file_ops_output}")
    print(f"   Examples: {len(file_ops_examples)}")
    print(f"   - Generic tool usage: {len(generic_tool_examples)}")
    print(f"   - File editing: {len(file_editing_examples)}")
    
    print(f"\n💡 Next steps:")
    print(f"   1. Train rule generation model:")
    print(f"      python finetune_qwen3.py --training-data {rule_gen_output}")
    print(f"   2. Train file operations model:")
    print(f"      python finetune_qwen3.py --training-data {file_ops_output}")
    
    return 0


if __name__ == "__main__":
    exit(main())
