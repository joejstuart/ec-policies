#!/usr/bin/env python3
"""
Workflow script to validate candidate Rego code and add to training data if valid.

Usage:
    # Validate a single example
    python validate_and_add_training.py --validate "natural language" candidate.rego
    
    # Generate candidate, validate, and add if passes
    python validate_and_add_training.py --generate-and-validate "natural language"
    
    # Validate entire JSONL file
    python validate_and_add_training.py --validate-file training.jsonl
"""

import json
import sys
import sys
import argparse
from pathlib import Path
from typing import Optional
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from validate_rego_training import validate_training_example, ValidationResult, validate_jsonl_file


def load_test_case_definitions():
    """Load test case definitions from JSON file."""
    test_file = Path("../data/test_case_definitions.json")
    if test_file.exists():
        with open(test_file) as f:
            return json.load(f)
    return {}


def find_matching_test_case(natural_language: str, test_definitions: dict) -> Optional[dict]:
    """Find matching test case definition for natural language."""
    for key, definition in test_definitions.get("test_cases", {}).items():
        if definition["natural_language"].lower() == natural_language.lower():
            return definition
    return None


def validate_with_test_definitions(natural_language: str, rego_code: str, test_definitions: dict) -> ValidationResult:
    """Validate using predefined test cases."""
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from validate_rego_training import RegoValidator, TestCase
    
    validator = RegoValidator()
    
    # Find matching test case
    test_case_def = find_matching_test_case(natural_language, test_definitions)
    if not test_case_def:
        return ValidationResult(
            passed=False,
            errors=[f"No test case definition found for: {natural_language}"],
            test_results=[]
        )
    
    # Convert test definitions to TestCase objects
    test_cases = []
    for test in test_case_def["tests"]:
        test_cases.append(TestCase(
            name=test["name"],
            input_data=test["input"],
            should_deny=test["should_deny"],
            expected_deny_msg=test.get("expected_msg_contains")
        ))
    
    # Validate
    return validator.validate(rego_code, test_cases)


def add_to_training_data(natural_language: str, assistant_content: str, training_file: str = "data/qwen3-training-data.jsonl"):
    """Add validated example to training data file."""
    training_path = Path(training_file)
    
    # Create training example
    example = {
        "messages": [
            {
                "role": "system",
                "content": "You are an expert at writing Rego policy rules for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code.\n\n## Attestation Structure\n\nThe input structure is:\n- `input.attestations` - array of attestation objects\n- Each attestation has `statement.predicate` containing build information\n- For SLSA v0.2: tasks are at `attestation.statement.predicate.buildConfig.tasks`\n- For SLSA v1.0: tasks are at `attestation.statement.predicate.buildDefinition.resolvedDependencies`\n- Alternative path (some formats): `attestation.statement.predicate.buildDefinition.tasks`\n\n## Task Structure\n- `task.name` - task name\n- `task.invocation.parameters` - object with parameter key-value pairs\n- `task.invocation.parameters.<param_name>` - specific parameter value\n- `task.ref.bundle` - OCI bundle reference\n- `task.results` - array of task results\n- `task.status` - task status (e.g., \"Succeeded\")\n\n## Common Patterns\n- Iterate attestations: `some attestation in input.attestations`\n- Iterate tasks: `some task in attestation.statement.predicate.buildConfig.tasks`\n- Filter by name: `task.name == \"<name>\"`\n- Check parameter: `task.invocation.parameters.<param> == \"<value>\"`\n\nWrite Rego deny rules that check the attestation structure."
            },
            {
                "role": "user",
                "content": natural_language
            },
            {
                "role": "assistant",
                "content": assistant_content
            }
        ]
    }
    
    # Append to file
    with open(training_path, "a") as f:
        f.write(json.dumps(example) + "\n")
    
    print(f"✅ Added to {training_file}")


def main():
    parser = argparse.ArgumentParser(description="Validate and add Rego training examples")
    parser.add_argument("--validate", nargs=2, metavar=("NATURAL_LANG", "REGO_FILE"),
                       help="Validate a single example")
    parser.add_argument("--validate-file", metavar="JSONL_FILE",
                       help="Validate all examples in a JSONL file")
    parser.add_argument("--add-if-valid", action="store_true",
                       help="Add to training data if validation passes")
    parser.add_argument("--training-file", default="data/qwen3-training-data.jsonl",
                       help="Training data file (default: data/qwen3-training-data.jsonl)")
    
    args = parser.parse_args()
    
    # Load test definitions
    test_definitions = load_test_case_definitions()
    
    if args.validate:
        natural_language, rego_file = args.validate
        
        # Read Rego code
        with open(rego_file) as f:
            rego_code = f.read()
        
        # Validate
        if test_definitions:
            result = validate_with_test_definitions(natural_language, rego_code, test_definitions)
        else:
            result = validate_training_example(natural_language, rego_code)
        
        if result.passed:
            print("✅ Validation passed!")
            if args.add_if_valid:
                # Extract assistant content (assume it's the Rego code wrapped in markdown)
                assistant_content = f"```rego\n{rego_code}\n```\n\nThis rule validates the requirement."
                add_to_training_data(natural_language, assistant_content, args.training_file)
            sys.exit(0)
        else:
            print("❌ Validation failed:")
            for error in result.errors:
                print(f"  - {error}")
            sys.exit(1)
    
    elif args.validate_file:
        # Validate entire file
        validate_jsonl_file(args.validate_file)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
