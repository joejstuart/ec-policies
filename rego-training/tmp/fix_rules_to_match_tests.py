#!/usr/bin/env python3
"""
Fix Rego rules to match test case definitions.

Analyzes validation failures and updates Rego code to match test expectations.
"""

import json
import re
from pathlib import Path
from validate_and_add_training import (
    load_test_case_definitions,
    find_matching_test_case,
    validate_with_test_definitions
)
from validate_rego_training import RegoValidator, TestCase

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
    
    return '\n'.join(lines[start_idx:]).strip()

def extract_metadata(rego_content: str) -> dict:
    """Extract METADATA from Rego file."""
    metadata = {}
    title_match = re.search(r'#\s*title:\s*(.+?)(?:\n|$)', rego_content)
    if title_match:
        metadata['title'] = title_match.group(1).strip()
    return metadata

def analyze_test_failure(rego_code: str, test_case_def: dict, validator: RegoValidator) -> str:
    """Analyze test failure and generate fixed Rego code."""
    tests = test_case_def.get("tests", [])
    
    # Convert to TestCase objects
    test_cases = []
    for test in tests:
        test_cases.append(TestCase(
            name=test["name"],
            input_data=test["input"],
            should_deny=test["should_deny"],
            expected_deny_msg=test.get("expected_msg_contains")
        ))
    
    # Run each test to see what happens
    full_rego = validator.create_test_package(rego_code)
    
    for test_case in test_cases:
        success, opa_errors, deny_results = validator.run_opa_test(full_rego, test_case.input_data)
        
        if not success:
            continue
        
        has_deny = len(deny_results) > 0
        
        # If test expects no deny but we're getting denies, we need to make the rule more lenient
        # If test expects deny but we're not getting any, we need to make the rule stricter
        
        if not test_case.should_deny and has_deny:
            # Rule is too strict - it's denying when it shouldn't
            # Need to check what condition is causing the deny and make it conditional
            
            # For annotation checks: maybe annotations object doesn't exist, so we should check if it exists first
            if "annotation" in rego_code.lower():
                # Check if the issue is that annotations is empty/missing
                # Fix: Only check annotation if annotations object exists and is not empty
                if "annotations[" in rego_code:
                    # Pattern: not annotations["key"]
                    # Should be: not task.invocation.environment.annotations or not annotations["key"]
                    pattern = r'annotations\s*:=\s*task\.invocation\.environment\.annotations\s*\n\s*not\s+annotations\["([^"]+)"\]'
                    replacement = r'annotations := task.invocation.environment.annotations\n\tannotations\n\tnot annotations["\1"]'
                    fixed_code = re.sub(pattern, replacement, rego_code)
                    if fixed_code != rego_code:
                        return fixed_code
            
            # For label checks: similar fix
            if "label" in rego_code.lower() and "labels[" in rego_code:
                pattern = r'labels\s*:=\s*task\.invocation\.environment\.labels\s*\n\s*not\s+labels\["([^"]+)"\]'
                replacement = r'labels := task.invocation.environment.labels\n\tlabels\n\tnot labels["\1"]'
                fixed_code = re.sub(pattern, replacement, rego_code)
                if fixed_code != rego_code:
                    return fixed_code
        
        elif test_case.should_deny and not has_deny:
            # Rule is too lenient - it's not denying when it should
            # This is less common, but we might need to check the test data
            pass
    
    return rego_code  # Return original if we can't fix

def fix_rego_file(rego_file: Path, test_case_def: dict, validator: RegoValidator) -> bool:
    """Fix a Rego file to match test expectations."""
    with open(rego_file) as f:
        content = f.read()
    
    rego_code = extract_rego_code(content)
    if not rego_code:
        return False
    
    # Try to fix
    fixed_code = analyze_test_failure(rego_code, test_case_def, validator)
    
    if fixed_code != rego_code:
        # Replace the deny rule(s) in the file
        lines = content.split('\n')
        start_idx = None
        end_idx = len(lines)
        
        for i, line in enumerate(lines):
            if line.strip().startswith('deny '):
                if start_idx is None:
                    start_idx = i
            elif start_idx is not None:
                # Check if this is still part of the deny rule (indented) or a new section
                stripped = line.strip()
                if stripped and not stripped.startswith('\t') and not line.startswith('\t') and not line.startswith(' '):
                    # Found end of deny rules
                    if not stripped.startswith('#'):
                        end_idx = i
                        break
        
        if start_idx is not None:
            # Replace deny rules with fixed code
            new_lines = lines[:start_idx]
            new_lines.extend(fixed_code.split('\n'))
            # Add blank line if needed
            if end_idx < len(lines) and lines[end_idx].strip():
                new_lines.append('')
            new_lines.extend(lines[end_idx:])
            
            with open(rego_file, 'w') as f:
                f.write('\n'.join(new_lines))
            
            return True
    
    return False

def main():
    """Fix all Rego rules to match test case definitions."""
    rego_dir = Path("rego_rules")
    test_definitions = load_test_case_definitions()
    validator = RegoValidator()
    
    if not rego_dir.exists():
        print(f"Error: {rego_dir} does not exist")
        return
    
    rego_files = sorted(rego_dir.glob("*.rego"))
    print(f"Processing {len(rego_files)} Rego files...")
    
    fixed_count = 0
    still_failing = []
    
    for rego_file in rego_files:
        try:
            with open(rego_file) as f:
                rego_content = f.read()
            
            metadata = extract_metadata(rego_content)
            natural_language = metadata.get('title', '')
            
            if not natural_language:
                continue
            
            rego_code = extract_rego_code(rego_content)
            if not rego_code:
                continue
            
            # Validate
            result = validate_with_test_definitions(natural_language, rego_code, test_definitions)
            
            if not result.passed:
                # Try to fix
                test_case_def = find_matching_test_case(natural_language, test_definitions)
                if test_case_def:
                    if fix_rego_file(rego_file, test_case_def, validator):
                        # Re-validate
                        with open(rego_file) as f:
                            new_content = f.read()
                        new_code = extract_rego_code(new_content)
                        new_result = validate_with_test_definitions(natural_language, new_code, test_definitions)
                        
                        if new_result.passed:
                            fixed_count += 1
                            if fixed_count % 10 == 0:
                                print(f"  Fixed {fixed_count} files...")
                        else:
                            still_failing.append(rego_file.name)
                    else:
                        still_failing.append(rego_file.name)
                else:
                    still_failing.append(rego_file.name)
        except Exception as e:
            print(f"  Error processing {rego_file.name}: {e}")
            still_failing.append(rego_file.name)
    
    print(f"\n✅ Fixed {fixed_count} rules")
    if still_failing:
        print(f"   Still failing: {len(still_failing)}")
        print(f"   First 10: {', '.join(still_failing[:10])}")

if __name__ == "__main__":
    main()
