#!/usr/bin/env python3
"""
Generate training data from all Rego rules in rego_rules/ directory.

This script:
1. Reads each Rego file
2. Extracts natural language from METADATA
3. Extracts Rego code
4. Validates against test_case_definitions.json
5. Generates training data in JSONL format
"""

import json
import re
from pathlib import Path
from validate_and_add_training import (
    load_test_case_definitions,
    find_matching_test_case,
    validate_with_test_definitions
)

def extract_metadata(rego_content: str) -> dict:
    """Extract METADATA from Rego file."""
    metadata = {}
    
    # Extract title
    title_match = re.search(r'#\s*title:\s*(.+?)(?:\n|$)', rego_content)
    if title_match:
        metadata['title'] = title_match.group(1).strip()
    
    # Extract description
    desc_match = re.search(r'#\s*description:\s*>-?\s*\n((?:\s*#.*\n)*)', rego_content)
    if desc_match:
        desc_lines = desc_match.group(1)
        # Remove # and leading spaces from each line
        desc = '\n'.join([line.lstrip('#').strip() for line in desc_lines.split('\n') if line.strip()])
        metadata['description'] = desc
    
    return metadata

def extract_rego_code(rego_content: str) -> str:
    """Extract just the deny rule code from Rego file."""
    # Remove package and import lines, keep everything from first deny onwards
    lines = rego_content.split('\n')
    start_idx = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('deny '):
            start_idx = i
            break
    
    if start_idx is None:
        return ""
    
    # Get everything from first deny to end of file
    rego_code = '\n'.join(lines[start_idx:]).strip()
    return rego_code

def create_assistant_content(rego_code: str, natural_language: str) -> str:
    """Create assistant content with Rego code and explanation."""
    # Extract key steps from the natural language
    explanation = f"```rego\n{rego_code}\n```\n\n"
    explanation += "This rule validates the requirement by checking the attestation structure."
    
    return explanation

def generate_training_example(natural_language: str, rego_code: str) -> dict:
    """Create a training example in JSONL format."""
    system_prompt = """You are an expert at writing Rego policy rules for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code.

## Attestation Structure

The input structure is:
- `input.attestations` - array of attestation objects
- Each attestation has `statement.predicate` containing build information
- For SLSA v0.2: tasks are at `attestation.statement.predicate.buildConfig.tasks`
- For SLSA v1.0: tasks are at `attestation.statement.predicate.buildDefinition.resolvedDependencies`
- Alternative path (some formats): `attestation.statement.predicate.buildDefinition.tasks`

## Task Structure
- `task.name` - task name
- `task.invocation.parameters` - object with parameter key-value pairs
- `task.invocation.parameters.<param_name>` - specific parameter value
- `task.ref.bundle` - OCI bundle reference
- `task.results` - array of task results
- `task.status` - task status (e.g., "Succeeded")

## Common Patterns
- Iterate attestations: `some attestation in input.attestations`
- Iterate tasks: `some task in attestation.statement.predicate.buildConfig.tasks`
- Filter by name: `task.name == "<name>"`
- Check parameter: `task.invocation.parameters.<param> == "<value>"`

Write Rego deny rules that check the attestation structure."""
    
    assistant_content = create_assistant_content(rego_code, natural_language)
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
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

def main():
    """Generate training data from all Rego rules."""
    rego_dir = Path("rego_rules")
    output_file = Path("data/qwen3-training-data.jsonl")
    test_definitions = load_test_case_definitions()
    
    if not rego_dir.exists():
        print(f"Error: {rego_dir} does not exist")
        return
    
    # Create data directory if it doesn't exist
    output_file.parent.mkdir(exist_ok=True)
    
    # Clear or backup existing file
    if output_file.exists():
        backup = output_file.with_suffix('.jsonl.backup')
        output_file.rename(backup)
        print(f"Backed up existing file to {backup}")
    
    rego_files = sorted(rego_dir.glob("*.rego"))
    print(f"Processing {len(rego_files)} Rego files...")
    
    validated_count = 0
    failed_count = 0
    skipped_count = 0
    
    with open(output_file, 'w') as out:
        for rego_file in rego_files:
            try:
                with open(rego_file) as f:
                    rego_content = f.read()
                
                # Extract metadata
                metadata = extract_metadata(rego_content)
                natural_language = metadata.get('title', '')
                
                if not natural_language:
                    print(f"  ⚠️  Skipping {rego_file.name}: No title found")
                    skipped_count += 1
                    continue
                
                # Extract Rego code
                rego_code = extract_rego_code(rego_content)
                if not rego_code:
                    print(f"  ⚠️  Skipping {rego_file.name}: No deny rule found")
                    skipped_count += 1
                    continue
                
                # Validate
                if test_definitions:
                    result = validate_with_test_definitions(natural_language, rego_code, test_definitions)
                else:
                    print(f"  ⚠️  No test definitions found, skipping validation for {rego_file.name}")
                    result = None
                
                if result and not result.passed:
                    print(f"  ❌ Failed validation: {rego_file.name}")
                    for error in result.errors:
                        print(f"     - {error}")
                    failed_count += 1
                    continue
                
                # Generate training example
                example = generate_training_example(natural_language, rego_code)
                
                # Write to JSONL file
                out.write(json.dumps(example) + '\n')
                validated_count += 1
                
                if validated_count % 50 == 0:
                    print(f"  Processed {validated_count} files...")
                    
            except Exception as e:
                print(f"  ❌ Error processing {rego_file.name}: {e}")
                failed_count += 1
    
    print(f"\n✅ Generated training data:")
    print(f"   Validated and added: {validated_count}")
    print(f"   Failed validation: {failed_count}")
    print(f"   Skipped: {skipped_count}")
    print(f"   Output: {output_file}")

if __name__ == "__main__":
    main()
