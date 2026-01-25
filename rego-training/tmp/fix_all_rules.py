#!/usr/bin/env python3
"""
Fix all Rego rules to match test case definitions.

This script analyzes test failures and systematically fixes rules.
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

def fix_annotation_rule(rego_code: str) -> str:
    """Fix annotation checking rules to handle empty annotations."""
    # Pattern: annotations := ... \n not annotations["key"]
    # Fix: Add check that annotations exist and are not empty
    pattern = r'(annotations\s*:=\s*task\.invocation\.environment\.annotations)\s*\n(\s*not\s+annotations\["([^"]+)"\])'
    
    def replacement(match):
        indent = '\t'
        return f'{match.group(1)}\n{indent}{match.group(1).split(":=")[0].strip()}\n{indent}count({match.group(1).split(":=")[0].strip()}) > 0\n{indent}{match.group(2)}'
    
    fixed = re.sub(pattern, replacement, rego_code)
    
    # If pattern didn't match, try a simpler approach
    if fixed == rego_code:
        # Add annotations check before not annotations["key"]
        pattern2 = r'(annotations\s*:=\s*task\.invocation\.environment\.annotations)\s*\n(\s*)(not\s+annotations\["[^"]+"\])'
        def repl2(match):
            indent = match.group(2)
            var_name = match.group(1).split(':=')[0].strip()
            return f'{match.group(1)}\n{indent}{var_name}\n{indent}count({var_name}) > 0\n{indent}{match.group(3)}'
        fixed = re.sub(pattern2, repl2, rego_code)
    
    return fixed

def fix_label_rule(rego_code: str) -> str:
    """Fix label checking rules to handle empty labels."""
    pattern = r'(labels\s*:=\s*task\.invocation\.environment\.labels)\s*\n(\s*)(not\s+labels\["[^"]+"\])'
    def replacement(match):
        indent = match.group(2)
        var_name = match.group(1).split(':=')[0].strip()
        return f'{match.group(1)}\n{indent}{var_name}\n{indent}count({var_name}) > 0\n{indent}{match.group(3)}'
    return re.sub(pattern, replacement, rego_code)

def fix_rego_file(rego_file: Path, test_case_def: dict, validator: RegoValidator) -> bool:
    """Fix a Rego file to match test expectations."""
    with open(rego_file) as f:
        content = f.read()
    
    rego_code = extract_rego_code(content)
    if not rego_code:
        return False
    
    # Try different fixes based on the rule type
    fixed_code = rego_code
    
    # Fix annotation rules
    if "annotation" in rego_code.lower() and "annotations[" in rego_code:
        fixed_code = fix_annotation_rule(fixed_code)
    
    # Fix label rules
    if "label" in rego_code.lower() and "labels[" in rego_code:
        fixed_code = fix_label_rule(fixed_code)
    
    if fixed_code == rego_code:
        return False  # No fix applied
    
    # Replace in file
    lines = content.split('\n')
    start_idx = None
    end_idx = len(lines)
    
    for i, line in enumerate(lines):
        if line.strip().startswith('deny '):
            if start_idx is None:
                start_idx = i
        elif start_idx is not None:
            stripped = line.strip()
            if stripped and not line.startswith('\t') and not line.startswith(' '):
                if not stripped.startswith('#'):
                    end_idx = i
                    break
    
    if start_idx is not None:
        new_lines = lines[:start_idx]
        new_lines.extend(fixed_code.split('\n'))
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

if __name__ == "__main__":
    main()
