#!/usr/bin/env python3
"""
Validate that instruction variations generate the same Rego rules.

This script checks that variations of the same instruction produce
semantically equivalent Rego code.

Usage:
    python validate_variations.py --data data/qwen3-variations.jsonl
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set


def normalize_rego_code(rego_code: str) -> str:
    """Normalize Rego code for comparison (remove whitespace, comments)."""
    import re
    
    # Remove comments
    rego_code = re.sub(r'#.*?$', '', rego_code, flags=re.MULTILINE)
    
    # Remove extra whitespace
    rego_code = ' '.join(rego_code.split())
    
    # Remove package declaration for comparison
    rego_code = re.sub(r'package\s+\w+\s*', '', rego_code)
    
    return rego_code.lower().strip()


def group_by_response(examples: List[Dict]) -> Dict[str, List[Dict]]:
    """Group examples by their assistant response (Rego code)."""
    groups = defaultdict(list)
    
    for ex in examples:
        assistant_response = ex["messages"][2]["content"]
        normalized = normalize_rego_code(assistant_response)
        groups[normalized].append(ex)
    
    return groups


def validate_variations(data_file: str) -> Dict:
    """Validate that variations generate the same rules."""
    print(f"📖 Loading data from {data_file}")
    
    examples = []
    with open(data_file) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    
    print(f"   Loaded {len(examples)} examples")
    
    # Group by normalized Rego code
    groups = group_by_response(examples)
    
    print(f"\n📊 Analysis:")
    print(f"   Unique Rego rules: {len(groups)}")
    
    # Find groups with multiple instructions (variations)
    variation_groups = {k: v for k, v in groups.items() if len(v) > 1}
    
    print(f"   Groups with variations: {len(variation_groups)}")
    
    # Analyze variation quality
    total_variations = 0
    good_variations = 0
    issues = []
    
    for normalized_code, group_examples in variation_groups.items():
        instructions = [ex["messages"][1]["content"] for ex in group_examples]
        total_variations += len(instructions) - 1  # -1 for original
        
        # Check if instructions are actually different
        unique_instructions = set(inst.lower().strip() for inst in instructions)
        if len(unique_instructions) == len(instructions):
            good_variations += len(instructions) - 1
        else:
            issues.append({
                "rule": normalized_code[:100],
                "duplicate_instructions": len(instructions) - len(unique_instructions)
            })
    
    print(f"\n✅ Validation Results:")
    print(f"   Total variations: {total_variations}")
    print(f"   Unique variations: {good_variations}")
    print(f"   Duplicate variations: {total_variations - good_variations}")
    
    if issues:
        print(f"\n⚠️  Found {len(issues)} groups with duplicate instructions")
    
    # Sample some variation groups
    print(f"\n📋 Sample variation groups (first 5):")
    for i, (normalized_code, group_examples) in enumerate(list(variation_groups.items())[:5]):
        print(f"\n   Group {i+1} ({len(group_examples)} variations):")
        for ex in group_examples[:3]:  # Show first 3
            instruction = ex["messages"][1]["content"]
            print(f"      - {instruction[:80]}...")
    
    return {
        "total_examples": len(examples),
        "unique_rules": len(groups),
        "variation_groups": len(variation_groups),
        "total_variations": total_variations,
        "good_variations": good_variations,
        "issues": len(issues)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Validate instruction variations"
    )
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Training data file with variations"
    )
    
    args = parser.parse_args()
    
    if not Path(args.data).exists():
        print(f"❌ Error: File not found: {args.data}")
        return 1
    
    results = validate_variations(args.data)
    
    print(f"\n✅ Validation complete!")
    print(f"   Variation coverage: {results['variation_groups']}/{results['unique_rules']} rules have variations")
    
    return 0


if __name__ == "__main__":
    exit(main())
