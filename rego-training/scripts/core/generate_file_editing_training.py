#!/usr/bin/env python3
"""
Generate training data for editing existing Rego policy files.

This script creates training examples that teach the model how to:
1. Add a new rule to an existing policy file
2. Maintain proper file structure (package, imports, metadata)
3. Place new rules in the correct location (after existing deny rules, before helpers)

The training examples show:
- Input: Existing file content + new requirement
- Output: Complete updated file with new rule added
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path for imports
parent_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(parent_dir))


def extract_package_and_imports(rego_content: str) -> Tuple[Optional[str], List[str]]:
    """Extract package declaration and imports from Rego file."""
    lines = rego_content.split('\n')
    package = None
    imports = []
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('package '):
            package = stripped
        elif stripped.startswith('import '):
            imports.append(stripped)
    
    return package, imports


def extract_metadata_blocks(rego_content: str) -> List[str]:
    """Extract all METADATA blocks from Rego file."""
    metadata_blocks = []
    
    # Pattern to match METADATA blocks
    pattern = r'(#\s*METADATA\s*\n(?:#.*\n)*)'
    matches = re.finditer(pattern, rego_content, re.MULTILINE)
    
    for match in matches:
        metadata_blocks.append(match.group(1))
    
    return metadata_blocks


def extract_deny_rules(rego_content: str) -> List[Tuple[str, str]]:
    """
    Extract deny rules with their metadata.
    Returns list of (metadata, rule) tuples.
    """
    rules = []
    lines = rego_content.split('\n')
    
    i = 0
    while i < len(lines):
        # Look for METADATA block
        if lines[i].strip().startswith('# METADATA'):
            metadata_start = i
            # Collect metadata lines
            metadata_lines = [lines[i]]
            i += 1
            while i < len(lines) and (lines[i].strip().startswith('#') or lines[i].strip() == ''):
                metadata_lines.append(lines[i])
                i += 1
            
            # Look for deny rule after metadata
            if i < len(lines) and 'deny' in lines[i]:
                rule_start = i
                # Find the end of the deny rule (matching braces)
                brace_count = 0
                rule_lines = []
                j = i
                while j < len(lines):
                    line = lines[j]
                    rule_lines.append(line)
                    brace_count += line.count('{')
                    brace_count -= line.count('}')
                    if brace_count == 0 and j > rule_start:
                        break
                    j += 1
                
                metadata = '\n'.join(metadata_lines)
                rule = '\n'.join(rule_lines)
                rules.append((metadata, rule))
                i = j + 1
            else:
                i += 1
        else:
            i += 1
    
    return rules


def extract_helper_rules(rego_content: str) -> str:
    """Extract helper rules (rules starting with _) and other non-deny rules."""
    lines = rego_content.split('\n')
    helper_start = None
    
    # Find the last deny rule
    last_deny_end = 0
    i = 0
    while i < len(lines):
        if 'deny' in lines[i] and 'contains' in lines[i]:
            # Find the end of this deny rule
            brace_count = 0
            j = i
            while j < len(lines):
                brace_count += lines[j].count('{')
                brace_count -= lines[j].count('}')
                if brace_count == 0 and j > i:
                    last_deny_end = j + 1
                    break
                j += 1
            i = j + 1
        else:
            i += 1
    
    # Everything after the last deny rule is helper rules
    if last_deny_end < len(lines):
        helper_lines = lines[last_deny_end:]
        # Skip empty lines at the start
        while helper_lines and not helper_lines[0].strip():
            helper_lines = helper_lines[1:]
        if helper_lines:
            return '\n'.join(helper_lines).strip()
    
    return ""


def combine_files(existing_file_content: str, new_rule_metadata: str, new_rule_code: str) -> str:
    """Combine existing file with new rule, maintaining proper structure."""
    package, imports = extract_package_and_imports(existing_file_content)
    existing_rules = extract_deny_rules(existing_file_content)
    helper_rules = extract_helper_rules(existing_file_content)
    
    # Build the new file
    parts = []
    
    # Package and imports
    if package:
        parts.append(package)
        parts.append('')
    if imports:
        parts.extend(imports)
        parts.append('')
    
    # Existing rules (with their metadata)
    for metadata, rule in existing_rules:
        parts.append(metadata)
        parts.append(rule)
        parts.append('')
    
    # New rule
    parts.append(new_rule_metadata)
    parts.append(new_rule_code)
    parts.append('')
    
    # Helper rules
    if helper_rules:
        parts.append(helper_rules)
    
    return '\n'.join(parts).rstrip() + '\n'


def extract_natural_language_from_metadata(metadata: str) -> Optional[str]:
    """Extract natural language requirement from METADATA title."""
    title_match = re.search(r'#\s*title:\s*(.+?)(?:\n|$)', metadata)
    if title_match:
        return title_match.group(1).strip()
    return None


def get_relative_file_path(file_path: Path, base_dir: Path = None) -> str:
    """Get a relative file path for display in training examples."""
    if base_dir:
        try:
            return str(file_path.relative_to(base_dir))
        except ValueError:
            pass
    return str(file_path)


def create_file_editing_training_example(
    existing_file_content: str,
    new_rule_metadata: str,
    new_rule_code: str,
    new_requirement: str,
    file_path: str = None
) -> Dict:
    """Create a training example for editing an existing file."""
    
    # Create the updated file
    updated_file = combine_files(existing_file_content, new_rule_metadata, new_rule_code)
    
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

## File Editing Guidelines

When adding a new rule to an existing policy file:
1. Keep the existing package declaration and imports
2. Add the new rule after existing deny rules
3. Place helper rules (starting with _) after all deny rules
4. Maintain proper formatting and spacing
5. Include METADATA annotations for the new rule
6. Preserve all existing rules and helpers

Write Rego deny rules that check the attestation structure."""
    
    # Use path-based prompt if file_path is provided, otherwise use full content
    if file_path:
        user_prompt = f"""Add a new rule to the existing Rego policy file at `{file_path}`.

**Current file content:**
```rego
{existing_file_content}
```

**New requirement:**
{new_requirement}

Provide the complete updated file with the new rule added in the correct location."""
    else:
        user_prompt = f"""I have an existing Rego policy file. Please add a new rule to it based on this requirement:

**Existing File:**
```rego
{existing_file_content}
```

**New Requirement:**
{new_requirement}

Please provide the complete updated file with the new rule added in the correct location."""
    
    assistant_content = f"""Here's the updated file with the new rule added:

```rego
{updated_file}
```

The new rule has been added after the existing deny rules, maintaining the proper file structure with package declaration, imports, and helper rules."""
    
    return {
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_prompt
            },
            {
                "role": "assistant",
                "content": assistant_content
            }
        ]
    }


def create_synthetic_multi_rule_file(base_files: List[Path], max_rules: int = 3) -> Optional[str]:
    """Create a synthetic multi-rule file by combining multiple single-rule files."""
    if len(base_files) < 2:
        return None
    
    # Take up to max_rules files
    selected_files = base_files[:max_rules]
    
    # Read first file to get package and imports
    with open(selected_files[0]) as f:
        first_content = f.read()
    
    package, imports = extract_package_and_imports(first_content)
    if not package:
        return None
    
    # Collect all rules
    all_rules = []
    for file in selected_files:
        with open(file) as f:
            content = f.read()
        rules = extract_deny_rules(content)
        all_rules.extend(rules)
    
    if not all_rules:
        return None
    
    # Build synthetic file
    parts = []
    if package:
        parts.append(package)
        parts.append('')
    if imports:
        parts.extend(imports)
        parts.append('')
    
    # Add all rules
    for metadata, rule in all_rules:
        parts.append(metadata)
        parts.append(rule)
        parts.append('')
    
    return '\n'.join(parts).rstrip() + '\n'


def main():
    """Generate training data for file editing."""
    rego_dir = Path("../rego_rules")
    policy_dir = Path("../../policy")
    output_file = Path("../data/qwen3-file-editing-training.jsonl")
    
    # Create data directory if it doesn't exist
    output_file.parent.mkdir(exist_ok=True)
    
    # Clear or backup existing file
    if output_file.exists():
        backup = output_file.with_suffix('.jsonl.backup')
        output_file.rename(backup)
        print(f"Backed up existing file to {backup}")
    
    examples_created = 0
    
    # Strategy 1: Use actual policy files with multiple rules
    policy_files = []
    if policy_dir.exists():
        # Look for policy files in release, task, pipeline directories
        for subdir in ["release", "task", "pipeline"]:
            policy_path = policy_dir / subdir
            if policy_path.exists():
                policy_files.extend(policy_path.rglob("*.rego"))
    
    # Filter out test files
    policy_files = [f for f in policy_files if not f.name.endswith("_test.rego")]
    
    # Strategy 2: Use training rego files to create synthetic multi-rule files
    rego_files = []
    if rego_dir.exists():
        rego_files = sorted([f for f in rego_dir.glob("*.rego") if not f.name.endswith("_test.rego")])
    
    print(f"Found {len(policy_files)} policy files and {len(rego_files)} training rego files")
    
    with open(output_file, 'w') as out:
        # Process actual policy files (they often have multiple rules)
        for policy_file in policy_files:
            try:
                with open(policy_file) as f:
                    existing_content = f.read()
                
                existing_rules = extract_deny_rules(existing_content)
                if len(existing_rules) < 1:
                    continue  # Skip files without deny rules
                
                # For each policy file, try to add a rule from training files
                # or from another policy file
                for new_rule_source in rego_files[:10]:  # Limit to avoid too many combinations
                    try:
                        with open(new_rule_source) as f:
                            new_rule_content = f.read()
                        
                        new_rules = extract_deny_rules(new_rule_content)
                        if not new_rules:
                            continue
                        
                        new_rule_metadata, new_rule_code = new_rules[0]
                        new_requirement = extract_natural_language_from_metadata(new_rule_metadata)
                        if not new_requirement:
                            continue
                        
                        # Get relative file path for the example
                        file_path = get_relative_file_path(policy_file, policy_dir)
                        
                        # Create training example with file path
                        example = create_file_editing_training_example(
                            existing_content,
                            new_rule_metadata,
                            new_rule_code,
                            new_requirement,
                            file_path=file_path
                        )
                        
                        out.write(json.dumps(example) + '\n')
                        examples_created += 1
                        
                        if examples_created >= 50:  # Limit examples from policy files
                            break
                    except:
                        continue
                
                if examples_created >= 50:
                    break
            except:
                continue
        
        # Strategy 3: Create synthetic multi-rule files from training files
        # Group files by prefix (e.g., task_*, step_*) to create related rules
        file_groups = {}
        for rego_file in rego_files:
            # Extract prefix (e.g., "task" from "task_023.rego")
            prefix = rego_file.stem.split('_')[0] if '_' in rego_file.stem else rego_file.stem
            if prefix not in file_groups:
                file_groups[prefix] = []
            file_groups[prefix].append(rego_file)
        
        # Create examples by combining files from same group
        for prefix, group_files in file_groups.items():
            if len(group_files) < 2:
                continue
            
            # Create synthetic existing file with 2-3 rules
            for i in range(0, len(group_files) - 1, 2):
                if i + 1 >= len(group_files):
                    break
                
                base_files = group_files[i:i+2]  # Use 2 files as base
                existing_content = create_synthetic_multi_rule_file(base_files, max_rules=2)
                if not existing_content:
                    continue
                
                # Use next file as new rule source
                if i + 2 < len(group_files):
                    new_rule_file = group_files[i + 2]
                else:
                    # Use a file from a different group
                    other_groups = [g for k, g in file_groups.items() if k != prefix]
                    if not other_groups:
                        continue
                    new_rule_file = other_groups[0][0]
                
                try:
                    with open(new_rule_file) as f:
                        new_rule_content = f.read()
                    
                    new_rules = extract_deny_rules(new_rule_content)
                    if not new_rules:
                        continue
                    
                    new_rule_metadata, new_rule_code = new_rules[0]
                    new_requirement = extract_natural_language_from_metadata(new_rule_metadata)
                    if not new_requirement:
                        continue
                    
                    # Create training example (synthetic files don't have real paths)
                    example = create_file_editing_training_example(
                        existing_content,
                        new_rule_metadata,
                        new_rule_code,
                        new_requirement,
                        file_path=None  # No path for synthetic files
                    )
                    
                    out.write(json.dumps(example) + '\n')
                    examples_created += 1
                    
                    if examples_created % 50 == 0:
                        print(f"  Created {examples_created} examples...")
                except Exception as e:
                    continue
    
    print(f"\n✅ Generated file editing training data:")
    print(f"   Examples created: {examples_created}")
    print(f"   Output: {output_file}")


if __name__ == "__main__":
    main()
