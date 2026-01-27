#!/usr/bin/env python3
"""
Generate training data for editing existing Rego policy files WITH TOOL USAGE.

This variant teaches the model to:
1. Use read_file tool to read existing files
2. Edit the file content
3. Use write_file tool to save the updated file

This is different from the non-tool version which just generates the complete file content.
"""

import importlib.util
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path for imports
parent_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(parent_dir))

# Import functions from the base script
import importlib.util
spec = importlib.util.spec_from_file_location(
    "generate_file_editing_training",
    Path(__file__).parent / "generate_file_editing_training.py"
)
base_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base_module)

# Import functions
extract_package_and_imports = base_module.extract_package_and_imports
extract_deny_rules = base_module.extract_deny_rules
extract_helper_rules = base_module.extract_helper_rules
combine_files = base_module.combine_files
extract_natural_language_from_metadata = base_module.extract_natural_language_from_metadata
get_relative_file_path = base_module.get_relative_file_path
create_synthetic_multi_rule_file = base_module.create_synthetic_multi_rule_file


def create_tool_based_training_example(
    existing_file_content: str,
    new_rule_metadata: str,
    new_rule_code: str,
    new_requirement: str,
    file_path: str = None
) -> Dict:
    """Create a training example that uses tools to read and write files."""
    
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
1. First, read the existing file using the read_file tool
2. Keep the existing package declaration and imports
3. Add the new rule after existing deny rules
4. Place helper rules (starting with _) after all deny rules
5. Maintain proper formatting and spacing
6. Include METADATA annotations for the new rule
7. Preserve all existing rules and helpers
8. Save the updated file using the write_file tool

## Available Tools

You have access to these tools:
- `read_file(path)`: Read the contents of a file at the given path
- `write_file(path, contents)`: Write contents to a file at the given path

**Note:** These tools are provided by the inference system. You only need to know their names and parameters. The system will execute them when you make tool calls.

Write Rego deny rules that check the attestation structure."""
    
    # Create user prompt
    if file_path:
        user_prompt = f"""Add a new rule to the existing Rego policy file at `{file_path}`.

**New requirement:**
{new_requirement}

Use the read_file tool to read the current file, then add the new rule and save it with write_file."""
    else:
        user_prompt = f"""I need to add a new rule to an existing Rego policy file.

**File content (for reference):**
```rego
{existing_file_content}
```

**New requirement:**
{new_requirement}

Use the read_file tool to read the file, then add the new rule and save it with write_file."""
    
    # Create assistant response with tool calls in proper format
    # Qwen3 uses JSON format in tool_calls, with separate tool response messages
    if file_path:
        # Generate unique IDs for tool calls
        read_call_id = f"call_{uuid.uuid4().hex[:12]}"
        write_call_id = f"call_{uuid.uuid4().hex[:12]}"
        
        # Assistant message with tool_calls
        # Embed tool calls in assistant content text
        assistant_content = f"""I'll read the existing file, add the new rule, and save it.

<tool_call>
name: read_file
arguments: {json.dumps({"path": file_path})}
</tool_call>"""
        
        # Tool response message
        tool_response_1_content = f"""```rego
{existing_file_content}
```"""
        
        # Second assistant message with embedded tool call
        assistant_content_2 = f"""Now I'll add the new rule and save the updated file.

<tool_call>
name: write_file
arguments: {json.dumps({
    "path": file_path,
    "contents": updated_file
})}
</tool_call>"""
        
        # Second tool response
        tool_response_2_content = """File written successfully."""
        
        # Final assistant message
        assistant_content_3 = f"""I've successfully added the new rule to `{file_path}`. The new rule has been placed after the existing deny rules, maintaining the proper file structure with package declaration, imports, and helper rules."""
        
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
                },
                {
                    "role": "tool",
                    "content": tool_response_1_content,
                    "tool_call_id": read_call_id
                },
                {
                    "role": "assistant",
                    "content": assistant_content_2
                },
                {
                    "role": "tool",
                    "content": tool_response_2_content,
                    "tool_call_id": write_call_id
                },
                {
                    "role": "assistant",
                    "content": assistant_content_3
                }
            ]
        }
    else:
        # For synthetic files without paths, use placeholder path
        placeholder_path = "policy/release/example/example.rego"
        
        # Generate unique IDs for tool calls
        read_call_id = f"call_{uuid.uuid4().hex[:12]}"
        write_call_id = f"call_{uuid.uuid4().hex[:12]}"
        
        # Embed tool calls in assistant content text
        assistant_content = f"""I'll read the existing file, add the new rule, and save it.

<tool_call>
name: read_file
arguments: {json.dumps({"path": placeholder_path})}
</tool_call>"""
        
        tool_response_1_content = f"""```rego
{existing_file_content}
```"""
        
        assistant_content_2 = f"""Now I'll add the new rule and save the updated file.

<tool_call>
name: write_file
arguments: {json.dumps({
    "path": placeholder_path,
    "contents": updated_file
})}
</tool_call>"""
        
        tool_response_2_content = """File written successfully."""
        
        assistant_content_3 = f"""I've successfully added the new rule. The new rule has been placed after the existing deny rules, maintaining the proper file structure with package declaration, imports, and helper rules."""
        
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
                },
                {
                    "role": "tool",
                    "content": tool_response_1_content,
                    "tool_call_id": read_call_id
                },
                {
                    "role": "assistant",
                    "content": assistant_content_2
                },
                {
                    "role": "tool",
                    "content": tool_response_2_content,
                    "tool_call_id": write_call_id
                },
                {
                    "role": "assistant",
                    "content": assistant_content_3
                }
            ]
        }


def main():
    """Generate training data for file editing with tool usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate file editing training data with tool usage")
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: data/qwen3-file-editing-tools-training.jsonl)"
    )
    
    args = parser.parse_args()
    
    # Resolve paths relative to project root (rego-training/)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent.parent
    
    rego_dir = project_root / "rego_rules"
    policy_dir = project_root.parent / "policy"
    
    if args.output:
        # Use provided output path
        output_file = Path(args.output)
        if not output_file.is_absolute():
            # Try relative to current directory first, then project root
            if Path(args.output).exists() or Path.cwd() != project_root:
                output_file = Path(args.output).resolve()
            else:
                output_file = project_root / args.output
    else:
        # Default output file
        output_file = project_root / "data/qwen3-file-editing-tools-training.jsonl"
    
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
                        
                        # Create training example with tool usage
                        example = create_tool_based_training_example(
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
                    
                    # Create training example with tool usage (no path for synthetic files)
                    example = create_tool_based_training_example(
                        existing_content,
                        new_rule_metadata,
                        new_rule_code,
                        new_requirement,
                        file_path=None
                    )
                    
                    out.write(json.dumps(example) + '\n')
                    examples_created += 1
                    
                    if examples_created % 50 == 0:
                        print(f"  Created {examples_created} examples...")
                except Exception as e:
                    continue
    
    print(f"\n✅ Generated file editing training data (with tools):")
    print(f"   Examples created: {examples_created}")
    print(f"   Output: {output_file}")


if __name__ == "__main__":
    main()
