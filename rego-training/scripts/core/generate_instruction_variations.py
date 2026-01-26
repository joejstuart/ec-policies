#!/usr/bin/env python3
"""
Generate instruction variations for training data augmentation.

This script creates multiple phrasings of the same requirement to make
the model robust to different ways users might express the same need.

Usage:
    python generate_instruction_variations.py \
      --input data/qwen3-complete-training.jsonl \
      --output data/qwen3-variations.jsonl \
      --variations-per-example 4
"""

import argparse
import json
import random
import re
from pathlib import Path
from typing import Dict, List


# Variation templates
ACTION_VERBS = {
    "verify": ["check", "ensure", "validate", "confirm", "require", "enforce"],
    "check": ["verify", "ensure", "validate", "confirm"],
    "ensure": ["verify", "check", "validate", "guarantee"],
    "validate": ["verify", "check", "ensure", "confirm"],
}

QUANTIFIERS = {
    "all": ["every", "each", "any", "all of the"],
    "every": ["all", "each", "any"],
    "each": ["all", "every", "any"],
    "at least one": ["one or more", "some", "at minimum one"],
}

STRUCTURE_PATTERNS = [
    # Pattern: "Verify X has Y"
    {
        "original": "verify {subject} has {property}",
        "variations": [
            "check that {subject} has {property}",
            "ensure {subject} has {property}",
            "{subject} must have {property}",
            "{subject} should have {property}",
            "validate that {subject} contains {property}",
            "require {subject} to have {property}",
        ]
    },
    # Pattern: "Verify all X have Y"
    {
        "original": "verify all {subject} have {property}",
        "variations": [
            "check that every {subject} has {property}",
            "ensure all {subject} have {property}",
            "all {subject} must have {property}",
            "every {subject} should have {property}",
            "validate that each {subject} contains {property}",
        ]
    },
    # Pattern: "Verify X is Y"
    {
        "original": "verify {subject} is {value}",
        "variations": [
            "check that {subject} is {value}",
            "ensure {subject} is {value}",
            "{subject} must be {value}",
            "{subject} should be {value}",
            "validate that {subject} equals {value}",
        ]
    },
    # Pattern: "Verify X exists"
    {
        "original": "verify {subject} exists",
        "variations": [
            "check that {subject} exists",
            "ensure {subject} is present",
            "{subject} must exist",
            "{subject} should be present",
            "validate that {subject} is available",
        ]
    },
]


def extract_instruction_components(instruction: str) -> Dict:
    """Extract components from instruction for pattern matching."""
    instruction_lower = instruction.lower()
    
    # Try to identify pattern
    components = {
        "action": None,
        "subject": None,
        "property": None,
        "value": None,
        "quantifier": None,
    }
    
    # Extract action verb
    for verb in ["verify", "check", "ensure", "validate", "require"]:
        if instruction_lower.startswith(verb):
            components["action"] = verb
            break
    
    # Extract quantifier
    for quant in ["all", "every", "each", "at least one"]:
        if quant in instruction_lower:
            components["quantifier"] = quant
            break
    
    return components


def generate_synonym_variations(instruction: str) -> List[str]:
    """Generate variations using synonym replacement."""
    variations = []
    
    # Preserve quoted strings and case
    # Extract quoted strings to preserve them
    quoted_strings = re.findall(r"'[^']*'|\"[^\"]*\"", instruction)
    instruction_work = instruction
    
    # Replace quoted strings with placeholders (preserve case)
    placeholders = {}
    for i, quoted in enumerate(quoted_strings):
        placeholder = f"__QUOTED_{i}__"
        placeholders[placeholder] = quoted
        placeholders[placeholder.lower()] = quoted  # Also map lowercase version
        instruction_work = instruction_work.replace(quoted, placeholder, 1)
    
    instruction_lower = instruction_work.lower()
    
    # Replace action verbs (word boundary aware)
    for original, synonyms in ACTION_VERBS.items():
        pattern = r'\b' + re.escape(original) + r'\b'
        if re.search(pattern, instruction_lower):
            for synonym in synonyms[:3]:  # Limit synonyms per verb
                variation = re.sub(pattern, synonym, instruction_lower, count=1)
                # Restore quoted strings (case-sensitive)
                for placeholder, quoted in placeholders.items():
                    variation = variation.replace(placeholder.lower(), quoted)
                # Capitalize first letter
                variation = variation[0].upper() + variation[1:] if variation else variation
                variations.append(variation)
    
    # Replace quantifiers (word boundary aware, but fix grammar)
    for original, synonyms in QUANTIFIERS.items():
        pattern = r'\b' + re.escape(original) + r'\b'
        if re.search(pattern, instruction_lower):
            for synonym in synonyms[:2]:  # Limit synonyms per quantifier
                variation = re.sub(pattern, synonym, instruction_lower, count=1)
                # Fix grammar: "every tasks" -> "every task"
                variation = re.sub(r'\bevery tasks\b', 'every task', variation)
                variation = re.sub(r'\beach tasks\b', 'each task', variation)
                # Restore quoted strings (case-sensitive)
                for placeholder, quoted in placeholders.items():
                    variation = variation.replace(placeholder.lower(), quoted)
                variation = variation[0].upper() + variation[1:] if variation else variation
                variations.append(variation)
    
    return variations[:3]  # Limit to 3 to avoid too many


def generate_structure_variations(instruction: str) -> List[str]:
    """Generate variations by restructuring the sentence."""
    variations = []
    instruction_lower = instruction.lower()
    
    # Pattern: "Verify X has Y" -> "X must have Y"
    if "verify" in instruction_lower and " has " in instruction_lower:
        # Extract subject and property
        parts = instruction_lower.split(" has ", 1)
        if len(parts) == 2:
            subject = parts[0].replace("verify ", "").replace("verify that ", "").strip()
            property_part = parts[1].strip()
            
            # Avoid "all all" or "every every"
            if not subject.startswith("all ") and not subject.startswith("every "):
                variations.append(f"{subject} must have {property_part}")
                variations.append(f"{subject} should have {property_part}")
            variations.append(f"ensure {subject} has {property_part}")
    
    # Pattern: "Verify all X have Y" -> "All X must have Y"
    if "verify all" in instruction_lower:
        # Remove "verify" and restructure
        rest = instruction_lower.replace("verify all ", "").replace("verify that all ", "")
        if not rest.startswith("all "):
            variations.append(f"all {rest}")
        # Fix grammar: "every tasks have" -> "every task has", "every tasks has" -> "every task has"
        rest_fixed = re.sub(r'\btasks\b', 'task', rest) if 'tasks' in rest else rest
        rest_fixed = re.sub(r'\bevery task have\b', 'every task has', rest_fixed)
        variations.append(f"every {rest_fixed}")
        variations.append(f"ensure all {rest}")
    
    # Pattern: "Verify X is Y" -> "X must be Y"
    if "verify" in instruction_lower and " is " in instruction_lower:
        parts = instruction_lower.split(" is ", 1)
        if len(parts) == 2:
            subject = parts[0].replace("verify ", "").replace("verify that ", "").strip()
            value = parts[1].strip()
            variations.append(f"{subject} must be {value}")
            variations.append(f"{subject} should be {value}")
    
    # Fix grammar issues
    fixed_variations = []
    for v in variations:
        # Fix: "every task have" -> "every task has"
        v = re.sub(r'\bevery task have\b', 'every task has', v)
        v = re.sub(r'\beach task have\b', 'each task has', v)
        # Fix: "all tasks have" is correct, but "every tasks" -> "every task"
        v = re.sub(r'\bevery tasks\b', 'every task', v)
        v = re.sub(r'\beach tasks\b', 'each task', v)
        fixed_variations.append(v)
    
    # Capitalize first letter
    fixed_variations = [v[0].upper() + v[1:] if v and len(v) > 0 else v for v in fixed_variations]
    
    return fixed_variations[:3]


def generate_formality_variations(instruction: str) -> List[str]:
    """Generate variations with different formality levels."""
    variations = []
    instruction_lower = instruction.lower()
    
    # More formal
    if "verify" in instruction_lower:
        formal = instruction_lower.replace("verify", "validate that")
        variations.append(formal[0].upper() + formal[1:] if formal else formal)
    
    # More casual
    if "verify" in instruction_lower:
        casual = instruction_lower.replace("verify", "make sure")
        variations.append(casual[0].upper() + casual[1:] if casual else casual)
    
    # Direct requirement
    if "verify" in instruction_lower:
        direct = instruction_lower.replace("verify ", "").replace("verify that ", "")
        variations.append(f"Require {direct}")
    
    return variations[:2]


def generate_variations(instruction: str, max_variations: int = 4) -> List[str]:
    """Generate multiple variations of an instruction."""
    all_variations = []
    
    # Add synonym variations
    all_variations.extend(generate_synonym_variations(instruction))
    
    # Add structure variations
    all_variations.extend(generate_structure_variations(instruction))
    
    # Add formality variations
    all_variations.extend(generate_formality_variations(instruction))
    
    # Remove duplicates and original
    unique_variations = []
    seen = {instruction.lower()}
    for var in all_variations:
        var_lower = var.lower().strip()
        if var_lower not in seen and var_lower != instruction.lower():
            unique_variations.append(var)
            seen.add(var_lower)
    
    # Limit to max_variations
    return unique_variations[:max_variations]


def create_variation_example(original_example: Dict, variation_instruction: str) -> Dict:
    """Create a new training example with a variation instruction."""
    # Copy the original example structure
    new_example = {
        "messages": [
            original_example["messages"][0],  # System prompt (same)
            {
                "role": "user",
                "content": variation_instruction
            },
            original_example["messages"][2]  # Assistant response (same)
        ]
    }
    return new_example


def main():
    parser = argparse.ArgumentParser(
        description="Generate instruction variations for training data augmentation"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="data/qwen3-complete-training.jsonl",
        help="Input training data file (default: data/qwen3-complete-training.jsonl)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/qwen3-variations.jsonl",
        help="Output file for variations (default: data/qwen3-variations.jsonl)"
    )
    parser.add_argument(
        "--variations-per-example",
        type=int,
        default=4,
        help="Number of variations to generate per example (default: 4)"
    )
    parser.add_argument(
        "--only-rule-generation",
        action="store_true",
        help="Only generate variations for rule-generation examples (not test examples)"
    )
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"❌ Error: Input file not found: {input_path}")
        return 1
    
    print(f"📖 Loading training data from {input_path}")
    examples = []
    with open(input_path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    
    print(f"   Found {len(examples)} examples")
    
    # Filter to rule-generation examples if requested
    if args.only_rule_generation:
        rule_gen_examples = []
        for ex in examples:
            user_msg = ex["messages"][1]["content"].lower()
            # Rule generation examples don't mention "test" or "create test"
            if "test" not in user_msg or ("test" in user_msg and "create" not in user_msg and "write" not in user_msg):
                rule_gen_examples.append(ex)
        examples = rule_gen_examples
        print(f"   Filtered to {len(examples)} rule-generation examples")
    
    print(f"\n🔄 Generating variations...")
    all_examples = []
    variation_count = 0
    
    for i, example in enumerate(examples):
        # Keep original
        all_examples.append(example)
        
        # Get user instruction
        user_instruction = example["messages"][1]["content"]
        
        # Generate variations
        variations = generate_variations(user_instruction, args.variations_per_example)
        
        # Create new examples with variations
        for variation_instruction in variations:
            new_example = create_variation_example(example, variation_instruction)
            all_examples.append(new_example)
            variation_count += 1
        
        if (i + 1) % 50 == 0:
            print(f"   Processed {i + 1}/{len(examples)} examples, generated {variation_count} variations")
    
    print(f"\n✅ Generated {variation_count} variations")
    print(f"   Total examples: {len(all_examples)} (original: {len(examples)}, variations: {variation_count})")
    
    # Shuffle to avoid overfitting to specific phrasings
    random.seed(42)
    random.shuffle(all_examples)
    
    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"\n💾 Saving to {output_path}")
    with open(output_path, 'w') as f:
        for example in all_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"✅ Saved {len(all_examples)} examples to {output_path}")
    print(f"\nNext steps:")
    print(f"  1. Review sample variations: head -20 {output_path}")
    print(f"  2. Validate variations map to same rules")
    print(f"  3. Merge with original data if needed")
    print(f"  4. Fine-tune model on augmented dataset")
    
    return 0


if __name__ == "__main__":
    exit(main())
