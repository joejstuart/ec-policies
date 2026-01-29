#!/usr/bin/env python3
"""
Merge different training data files into a single training dataset.

This script combines:
1. Rule generation training (qwen3-training-data.jsonl)
2. Test creation training (qwen3-test-creation-training.jsonl)
3. File editing training (qwen3-file-editing-training.jsonl) - optional
4. Generic tool usage training (qwen3-generic-tool-usage-training.jsonl) - optional
5. SBOM training (qwen3-sbom-training-data.jsonl) - optional

Into a single comprehensive training file.
"""

import argparse
import json
from pathlib import Path
from typing import List, Dict, Optional


def load_jsonl(file_path: Path) -> List[Dict]:
    """Load examples from JSONL file."""
    examples = []
    # Resolve path relative to script directory if relative
    if not file_path.is_absolute():
        script_dir = Path(__file__).parent
        file_path = (script_dir / file_path).resolve()
    
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    examples.append(json.loads(line))
    else:
        print(f"   ⚠️  Warning: File not found: {file_path}")
    return examples


def main():
    # Get script directory and project root (parent of scripts/core)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent
    
    parser = argparse.ArgumentParser(description="Merge training data files")
    parser.add_argument(
        "--rule-data",
        type=str,
        default="data/qwen3-training-data.jsonl",
        help="Path to rule generation training data (relative to project root)"
    )
    parser.add_argument(
        "--test-data",
        type=str,
        default="data/qwen3-test-creation-training.jsonl",
        help="Path to test creation training data (relative to project root)"
    )
    parser.add_argument(
        "--file-editing-data",
        type=str,
        default=None,
        help="Path to file editing training data (relative to project root, optional)"
    )
    parser.add_argument(
        "--generic-tool-data",
        type=str,
        default=None,
        help="Path to generic tool usage training data (relative to project root, optional)"
    )
    parser.add_argument(
        "--sbom-data",
        type=str,
        default=None,
        help="Path to SBOM training data (relative to project root, optional)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/qwen3-complete-training.jsonl",
        help="Output path for merged training data (relative to project root)"
    )
    
    args = parser.parse_args()
    
    # Resolve all paths relative to project root
    # Handle both relative paths (data/...) and parent-relative paths (../data/...)
    def resolve_path(path_str):
        if path_str is None or path_str == "":
            return None
        path = Path(path_str)
        if path.is_absolute():
            return path
        
        # If path starts with ../, resolve from current working directory
        if path_str.startswith("../"):
            import os
            cwd = Path(os.getcwd())
            cwd_resolved = (cwd / path_str).resolve()
            # Check if it's within project root
            try:
                rel_path = cwd_resolved.relative_to(project_root)
                return project_root / rel_path
            except ValueError:
                # If not relative to project_root, return as-is
                return cwd_resolved
        
        # Otherwise, treat as relative to project root
        return project_root / path
    
    args.rule_data = resolve_path(args.rule_data)
    args.test_data = resolve_path(args.test_data)
    args.file_editing_data = resolve_path(args.file_editing_data) if args.file_editing_data else None
    args.generic_tool_data = resolve_path(args.generic_tool_data) if args.generic_tool_data else None
    args.sbom_data = resolve_path(args.sbom_data) if args.sbom_data else None
    args.output = resolve_path(args.output)
    
    print("=" * 70)
    print("Merging Training Data")
    print("=" * 70)
    
    # Load base training data (rule generation)
    print(f"\n📖 Loading rule generation training data...")
    rule_examples = load_jsonl(args.rule_data)
    print(f"   Found {len(rule_examples)} rule generation examples")
    
    # Load test creation training data (optional - skip if empty string)
    test_examples = []
    if args.test_data:
        print(f"\n📖 Loading test creation training data...")
        test_examples = load_jsonl(args.test_data)
        print(f"   Found {len(test_examples)} test creation examples")
    
    # Load file editing training data (optional)
    file_editing_examples = []
    if args.file_editing_data:
        print(f"\n📖 Loading file editing training data...")
        file_editing_examples = load_jsonl(args.file_editing_data)
        print(f"   Found {len(file_editing_examples)} file editing examples")
    else:
        # Try default path
        default_file_editing = project_root / "data/qwen3-file-editing-training.jsonl"
        if default_file_editing.exists():
            print(f"\n📖 Loading file editing training data (from default path)...")
            file_editing_examples = load_jsonl(default_file_editing)
            print(f"   Found {len(file_editing_examples)} file editing examples")
    
    # Load generic tool usage training data (optional)
    generic_tool_examples = []
    if args.generic_tool_data:
        print(f"\n📖 Loading generic tool usage training data...")
        generic_tool_examples = load_jsonl(args.generic_tool_data)
        print(f"   Found {len(generic_tool_examples)} generic tool usage examples")
    else:
        # Try default path
        default_generic_tool = project_root / "data/qwen3-generic-tool-usage-training.jsonl"
        if default_generic_tool.exists():
            print(f"\n📖 Loading generic tool usage training data (from default path)...")
            generic_tool_examples = load_jsonl(default_generic_tool)
            print(f"   Found {len(generic_tool_examples)} generic tool usage examples")
    
    # Load SBOM training data (optional)
    sbom_examples = []
    if args.sbom_data:
        print(f"\n📖 Loading SBOM training data...")
        sbom_examples = load_jsonl(args.sbom_data)
        print(f"   Found {len(sbom_examples)} SBOM training examples")
    else:
        # Try default path
        default_sbom = project_root / "sbom_data/qwen3-sbom-training-data.jsonl"
        if default_sbom.exists():
            print(f"\n📖 Loading SBOM training data (from default path)...")
            sbom_examples = load_jsonl(default_sbom)
            print(f"   Found {len(sbom_examples)} SBOM training examples")
    
    # Combine all examples
    all_examples = rule_examples + test_examples + file_editing_examples + generic_tool_examples + sbom_examples
    
    # Shuffle for better training (optional but recommended)
    import random
    random.seed(42)
    random.shuffle(all_examples)
    
    # Write merged file
    print(f"\n💾 Writing merged training data...")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        for example in all_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"\n✅ Merged training data created:")
    print(f"   Rule generation examples: {len(rule_examples)}")
    print(f"   Test creation examples: {len(test_examples)}")
    if file_editing_examples:
        print(f"   File editing examples: {len(file_editing_examples)}")
    if generic_tool_examples:
        print(f"   Generic tool usage examples: {len(generic_tool_examples)}")
    if sbom_examples:
        print(f"   SBOM training examples: {len(sbom_examples)}")
    print(f"   Total examples: {len(all_examples)}")
    print(f"   Output: {args.output}")
    
    # Show breakdown by type
    if test_examples:
        rule_to_test = sum(1 for ex in test_examples if "create a complete test file" in ex["messages"][1]["content"].lower())
        requirement_to_rule = len(test_examples) - rule_to_test
        
        print(f"\n📊 Test creation breakdown:")
        print(f"   Rule-to-Test examples: {rule_to_test}")
        print(f"   Requirement-to-Rule-and-Test examples: {requirement_to_rule}")
    
    return 0


if __name__ == "__main__":
    exit(main())
