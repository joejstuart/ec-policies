#!/usr/bin/env python3
"""
Generate additional training data for test creation scenarios.

This script creates two types of training examples:
1. Rule-to-Test: Given a Rego rule, create tests for it
2. Requirement-to-Rule-and-Test: Given a requirement, create both the rule and tests

These examples help the model learn:
- How to write tests for existing rules
- How to create both rules and tests from requirements
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


def extract_metadata(rego_content: str) -> Dict:
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
        desc = '\n'.join([line.lstrip('#').strip() for line in desc_lines.split('\n') if line.strip()])
        metadata['description'] = desc
    
    return metadata


def extract_rego_code(rego_content: str) -> str:
    """Extract just the deny rule code from Rego file."""
    lines = rego_content.split('\n')
    start_idx = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('deny '):
            start_idx = i
            break
    
    if start_idx is None:
        return ""
    
    rego_code = '\n'.join(lines[start_idx:]).strip()
    return rego_code


def extract_test_code(test_content: str) -> str:
    """Extract test code from test file."""
    # Remove package and import lines, keep test rules
    lines = test_content.split('\n')
    start_idx = None
    
    for i, line in enumerate(lines):
        if line.strip().startswith('test_'):
            start_idx = i
            break
    
    if start_idx is None:
        return ""
    
    test_code = '\n'.join(lines[start_idx:]).strip()
    return test_code


def format_rego_value(value, indent=0) -> str:
    """Format a Python value as Rego literal with proper indentation."""
    indent_str = "\t" * indent
    next_indent = indent + 1
    next_indent_str = "\t" * next_indent
    
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = []
        for k, v in value.items():
            key = json.dumps(str(k))
            formatted_value = format_rego_value(v, next_indent)
            items.append(f"{next_indent_str}{key}: {formatted_value}")
        return "{\n" + ",\n".join(items) + f"\n{indent_str}}}"
    elif isinstance(value, list):
        if not value:
            return "[]"
        items = [format_rego_value(item, next_indent) for item in value]
        if any(isinstance(item, (dict, list)) for item in value) or len(value) > 3:
            formatted_items = [f"{next_indent_str}{item}" for item in items]
            return "[\n" + ",\n".join(formatted_items) + f"\n{indent_str}]"
        else:
            return "[" + ", ".join(items) + "]"
    elif isinstance(value, str):
        return json.dumps(value)
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (int, float)):
        return str(value)
    elif value is None:
        return "null"
    else:
        return json.dumps(value)


def create_rule_to_test_example(rego_file: Path, test_file: Path, natural_language: str) -> Optional[Dict]:
    """Create training example: Given a Rego rule, create tests for it."""
    try:
        with open(rego_file) as f:
            rego_content = f.read()
        
        with open(test_file) as f:
            test_content = f.read()
        
        rego_code = extract_rego_code(rego_content)
        test_code = extract_test_code(test_content)
        
        if not rego_code or not test_code:
            return None
        
        # Extract package name
        package_match = re.search(r'^package\s+(\w+)', rego_content, re.MULTILINE)
        if not package_match:
            return None
        package_name = package_match.group(1)
        
        system_prompt = """You are an expert at writing OPA Rego test files. You understand how to create comprehensive test cases for Rego policy rules following OPA testing best practices.

## OPA Testing Best Practices

1. **Test File Structure**:
   - Test files end with `_test.rego`
   - Test package uses `_test` suffix: `package {rule_package}_test`
   - Import the rule: `import data.{rule_package}`
   - Use `import rego.v1` for modern Rego syntax

2. **Test Rules**:
   - Test rules are prefixed with `test_`
   - Use `with input as {...}` to provide test data
   - For rules that should deny: `count({package}.deny) > 0`
   - For rules that should pass: `count({package}.deny) == 0`
   - All object keys in test data must be quoted strings

3. **Test Coverage**:
   - Create both positive (should deny) and negative (should pass) test cases
   - Use realistic attestation data from the Enterprise Contract structure
   - Test edge cases and boundary conditions

4. **Test Data**:
   - Use complete attestation structures with all required fields
   - Ensure test data matches the rule's validation requirements
   - Include both valid and invalid scenarios

Write comprehensive test files that provide full coverage of the Rego rule."""
        
        user_message = f"""Given the following Rego policy rule, create a complete test file for it.

**Requirement**: {natural_language}

**Rego Rule**:
```rego
package {package_name}

{rego_code}
```

Create a `{package_name}_test.rego` file with comprehensive test cases."""
        
        assistant_message = f"""Here is a complete test file for the rule:

```rego
package {package_name}_test

import rego.v1
import data.{package_name}

{test_code}
```

This test file includes:
- Both positive test cases (where the rule should deny) and negative test cases (where the rule should pass)
- Realistic attestation data that exercises the rule's validation logic
- Proper use of `with input as` to provide test data
- All object keys properly quoted to avoid unsafe variable errors

The tests verify that the rule correctly validates the requirement: {natural_language}"""
        
        return {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
                {"role": "assistant", "content": assistant_message}
            ]
        }
    except Exception as e:
        print(f"  ⚠️  Error creating rule-to-test example for {rego_file.name}: {e}")
        return None


def create_requirement_to_rule_and_test_example(
    natural_language: str,
    rego_code: str,
    test_code: str,
    package_name: str
) -> Dict:
    """Create training example: Given a requirement, create both rule and tests."""
    
    system_prompt = """You are an expert at writing OPA Rego policy rules and their corresponding test files for Enterprise Contract. You understand the structure of Tekton PipelineRun attestations and can translate natural language policy requirements into Rego code with comprehensive tests.

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

## OPA Testing Best Practices

1. **Test File Structure**:
   - Test files end with `_test.rego`
   - Test package uses `_test` suffix: `package {rule_package}_test`
   - Import the rule: `import data.{rule_package}`
   - Use `import rego.v1` for modern Rego syntax

2. **Test Rules**:
   - Test rules are prefixed with `test_`
   - Use `with input as {...}` to provide test data
   - For rules that should deny: `count({package}.deny) > 0`
   - For rules that should pass: `count({package}.deny) == 0`
   - All object keys in test data must be quoted strings

3. **Test Coverage**:
   - Create both positive (should deny) and negative (should pass) test cases
   - Use realistic attestation data
   - Test edge cases and boundary conditions

Write Rego deny rules that check the attestation structure, and create comprehensive test files for each rule."""
    
    user_message = f"""I need a Rego policy rule to validate the following requirement, along with a complete test file for it.

**Requirement**: {natural_language}

Create:
1. A Rego rule file (`{package_name}.rego`) that implements the validation
2. A corresponding test file (`{package_name}_test.rego`) with comprehensive test cases"""
    
    assistant_message = f"""Here is the complete Rego rule and test file:

**{package_name}.rego**:
```rego
package {package_name}

import rego.v1

{rego_code}
```

**{package_name}_test.rego**:
```rego
package {package_name}_test

import rego.v1
import data.{package_name}

{test_code}
```

The rule validates: {natural_language}

The test file includes:
- Both positive test cases (where the rule should deny) and negative test cases (where the rule should pass)
- Realistic attestation data that exercises the rule's validation logic
- Proper use of `with input as` to provide test data
- All object keys properly quoted to avoid unsafe variable errors"""
    
    return {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
            {"role": "assistant", "content": assistant_message}
        ]
    }


def main():
    rego_dir = Path("rego_rules")
    test_def_file = Path("../data/test_case_definitions.json")
    comprehensive_file = Path("../data/comprehensive_test_cases.json")
    output_file = Path("data/qwen3-test-creation-training.jsonl")
    
    if not rego_dir.exists():
        print(f"❌ Error: {rego_dir} does not exist")
        return 1
    
    if not test_def_file.exists():
        print(f"❌ Error: {test_def_file} does not exist")
        return 1
    
    if not comprehensive_file.exists():
        print(f"❌ Error: {comprehensive_file} does not exist")
        return 1
    
    # Load test case definitions
    print(f"📖 Loading test case definitions...")
    with open(test_def_file) as f:
        test_data = json.load(f)
        all_test_cases = test_data.get("test_cases", {})
    
    with open(comprehensive_file) as f:
        comprehensive_data = json.load(f)
        comprehensive_cases = comprehensive_data.get("test_cases", {})
    
    print(f"   Found {len(all_test_cases)} test case definitions")
    
    # Process each Rego file
    rego_files = sorted(rego_dir.glob("*.rego"))
    rego_files = [f for f in rego_files if not f.name.endswith("_test.rego")]
    
    print(f"\n📝 Processing {len(rego_files)} Rego files...")
    
    rule_to_test_count = 0
    requirement_to_rule_count = 0
    skipped_count = 0
    
    with open(output_file, 'w') as out:
        for rego_file in rego_files:
            try:
                rule_id = rego_file.stem
                test_file = rego_dir / f"{rule_id}_test.rego"
                
                # Get natural language from comprehensive test cases
                comprehensive_case = comprehensive_cases.get(rule_id)
                if not comprehensive_case:
                    skipped_count += 1
                    continue
                
                natural_language = comprehensive_case.get("natural_language", "")
                if not natural_language:
                    skipped_count += 1
                    continue
                
                # Read Rego file
                with open(rego_file) as f:
                    rego_content = f.read()
                
                rego_code = extract_rego_code(rego_content)
                if not rego_code:
                    skipped_count += 1
                    continue
                
                # Extract package name
                package_match = re.search(r'^package\s+(\w+)', rego_content, re.MULTILINE)
                if not package_match:
                    skipped_count += 1
                    continue
                package_name = package_match.group(1)
                
                # Type 1: Rule-to-Test (if test file exists)
                if test_file.exists():
                    example = create_rule_to_test_example(rego_file, test_file, natural_language)
                    if example:
                        out.write(json.dumps(example) + '\n')
                        rule_to_test_count += 1
                
                # Type 2: Requirement-to-Rule-and-Test (if test file exists)
                if test_file.exists():
                    with open(test_file) as f:
                        test_content = f.read()
                    test_code = extract_test_code(test_content)
                    if test_code:
                        example = create_requirement_to_rule_and_test_example(
                            natural_language, rego_code, test_code, package_name
                        )
                        out.write(json.dumps(example) + '\n')
                        requirement_to_rule_count += 1
                
            except Exception as e:
                print(f"  ❌ Error processing {rego_file.name}: {e}")
                import traceback
                traceback.print_exc()
                skipped_count += 1
    
    print(f"\n✅ Test creation training data generated:")
    print(f"   Rule-to-Test examples: {rule_to_test_count}")
    print(f"   Requirement-to-Rule-and-Test examples: {requirement_to_rule_count}")
    print(f"   Skipped: {skipped_count}")
    print(f"   Output: {output_file}")
    print(f"   Total examples: {rule_to_test_count + requirement_to_rule_count}")
    
    return 0


if __name__ == "__main__":
    exit(main())
