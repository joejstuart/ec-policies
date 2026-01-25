#!/usr/bin/env python3
"""
Generate OPA test files for each Rego rule using test data from test_case_definitions.json.

This script:
1. Reads all Rego rules from rego_rules/
2. Matches them with test cases in test_case_definitions.json
3. Generates _test.rego files following OPA testing best practices
4. Uses attestation data from test_case_definitions.json for test inputs

Based on OPA testing best practices:
- Test files end with _test.rego
- Test package uses _test suffix
- Test rules prefixed with test_
- Use 'with input as' for test data
- Import the policy package being tested
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, List, Optional


def extract_package_name(rego_content: str) -> Optional[str]:
    """Extract package name from Rego file."""
    match = re.search(r'^package\s+(\w+)', rego_content, re.MULTILINE)
    return match.group(1) if match else None


def format_rego_value(value, indent=0) -> str:
    """Format a Python value as Rego literal with proper indentation.
    
    All object keys are quoted to avoid unsafe variable errors in Rego.
    """
    indent_str = "\t" * indent
    next_indent = indent + 1
    next_indent_str = "\t" * next_indent
    
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = []
        for k, v in value.items():
            # Always quote keys to avoid unsafe variable errors
            key = json.dumps(str(k))
            formatted_value = format_rego_value(v, next_indent)
            items.append(f"{next_indent_str}{key}: {formatted_value}")
        return "{\n" + ",\n".join(items) + f"\n{indent_str}}}"
    elif isinstance(value, list):
        if not value:
            return "[]"
        items = [format_rego_value(item, next_indent) for item in value]
        # Format as multi-line if any item is complex
        if any(isinstance(item, (dict, list)) for item in value) or len(value) > 3:
            formatted_items = [f"{next_indent_str}{item}" for item in items]
            return "[\n" + ",\n".join(formatted_items) + f"\n{indent_str}]"
        else:
            return "[" + ", ".join(items) + "]"
    elif isinstance(value, str):
        # Use JSON encoding for proper escaping
        return json.dumps(value)
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (int, float)):
        return str(value)
    elif value is None:
        return "null"
    else:
        return json.dumps(value)


def generate_test_file(package_name: str, rule_file: str, test_cases: List[Dict]) -> str:
    """Generate Rego test file content following OPA best practices."""
    lines = [
        f"package {package_name}_test",
        "",
        "import rego.v1",
        f"import data.{package_name}",
        ""
    ]
    
    for test_case in test_cases:
        test_name = test_case.get("name", "unnamed_test")
        # Convert test name to valid Rego identifier
        # Remove common prefixes and clean up
        test_name = re.sub(r'^should_', '', test_name)
        test_name = re.sub(r'[^a-zA-Z0-9_]', '_', test_name)
        test_name = re.sub(r'_+', '_', test_name)  # Collapse multiple underscores
        test_name = test_name.strip('_')
        
        if not test_name.startswith("test_"):
            test_name = f"test_{test_name}"
        
        should_deny = test_case.get("should_deny", False)
        input_data = test_case.get("input", {})
        
        # Format input data
        input_str = format_rego_value(input_data, indent=1)
        
        # Format the test following OPA conventions
        if should_deny:
            # Test should produce a deny result (deny is not empty)
            lines.append(f"{test_name} if {{")
            lines.append(f'\tcount({package_name}.deny) > 0')
            lines.append(f'\twith input as {input_str}')
            lines.append("}")
        else:
            # Test should NOT produce a deny result (deny is empty)
            lines.append(f"{test_name} if {{")
            lines.append(f'\tcount({package_name}.deny) == 0')
            lines.append(f'\twith input as {input_str}')
            lines.append("}")
        
        lines.append("")
    
    return "\n".join(lines)


def main():
    rego_dir = Path("rego_rules")
    test_def_file = Path("test_case_definitions.json")
    output_dir = rego_dir  # Tests go in same directory as rules
    
    if not rego_dir.exists():
        print(f"❌ Error: {rego_dir} does not exist")
        return 1
    
    if not test_def_file.exists():
        print(f"❌ Error: {test_def_file} does not exist")
        return 1
    
    # Load test case definitions
    print(f"📖 Loading test case definitions from {test_def_file}...")
    with open(test_def_file) as f:
        test_data = json.load(f)
        all_test_cases = test_data.get("test_cases", {})
    
    print(f"   Found {len(all_test_cases)} test case definitions")
    
    # Process each Rego file
    rego_files = sorted(rego_dir.glob("*.rego"))
    rego_files = [f for f in rego_files if not f.name.endswith("_test.rego")]
    
    print(f"\n📝 Processing {len(rego_files)} Rego files...")
    
    created_count = 0
    skipped_count = 0
    error_count = 0
    
    for rego_file in rego_files:
        try:
            # Read Rego file
            with open(rego_file) as f:
                rego_content = f.read()
            
            # Extract package name
            package_name = extract_package_name(rego_content)
            if not package_name:
                print(f"  ⚠️  Skipping {rego_file.name}: No package name found")
                skipped_count += 1
                continue
            
            # Find matching test case (by package name or file name)
            rule_id = rego_file.stem  # filename without .rego
            test_case_data = all_test_cases.get(rule_id)
            
            if not test_case_data:
                print(f"  ⚠️  Skipping {rego_file.name}: No test case found for '{rule_id}'")
                skipped_count += 1
                continue
            
            # Get tests from test case
            tests = test_case_data.get("tests", [])
            if not tests:
                print(f"  ⚠️  Skipping {rego_file.name}: No tests in test case")
                skipped_count += 1
                continue
            
            # Generate test file
            test_file_content = generate_test_file(package_name, rego_file.name, tests)
            test_file_path = output_dir / f"{rule_id}_test.rego"
            
            # Write test file
            with open(test_file_path, 'w') as f:
                f.write(test_file_content)
            
            print(f"  ✅ Created {test_file_path.name} ({len(tests)} tests)")
            created_count += 1
            
        except Exception as e:
            print(f"  ❌ Error processing {rego_file.name}: {e}")
            import traceback
            traceback.print_exc()
            error_count += 1
    
    print(f"\n✅ Test generation complete:")
    print(f"   Created: {created_count}")
    print(f"   Skipped: {skipped_count}")
    print(f"   Errors: {error_count}")
    
    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    exit(main())
