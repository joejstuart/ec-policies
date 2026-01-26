#!/usr/bin/env python3
"""
Validate that test data generation is correct by checking a few sample cases.
"""

import json
import sys
from validate_and_add_training import load_test_case_definitions, find_matching_test_case, validate_with_test_definitions
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from validate_rego_training import RegoValidator, TestCase
import re
from pathlib import Path

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

def test_specific_cases():
    """Test specific cases to identify patterns."""
    test_defs = load_test_case_definitions()
    rego_dir = Path("rego_rules")
    
    # Test cases to check
    test_files = [
        "timestamp_216.rego",
        "timestamp_217.rego", 
        "task_result_073.rego",
        "annotation_050.rego",
        "compound_002.rego"
    ]
    
    validator = RegoValidator()
    
    for fname in test_files:
        fpath = rego_dir / fname
        if not fpath.exists():
            continue
        
        print(f"\n=== {fname} ===")
        
        with open(fpath) as f:
            content = f.read()
        
        lines = content.split('\n')
        start_idx = None
        for i, line in enumerate(lines):
            if line.strip().startswith('deny '):
                start_idx = i
                break
        
        if start_idx is None:
            print("  No deny rule found")
            continue
        
        rego_code = '\n'.join(lines[start_idx:]).strip()
        title_match = re.search(r'#\s*title:\s*(.+?)(?:\n|$)', content)
        nl = title_match.group(1).strip() if title_match else ""
        
        if not nl:
            print("  No title found")
            continue
        
        # Get test case definition
        test_case_def = find_matching_test_case(nl, test_defs)
        if not test_case_def:
            print(f"  No test case found for: {nl[:60]}...")
            continue
        
        # Convert to TestCase objects
        test_cases = []
        for test in test_case_def["tests"]:
            test_cases.append(TestCase(
                name=test["name"],
                input_data=test["input"],
                should_deny=test["should_deny"],
                expected_deny_msg=test.get("expected_msg_contains")
            ))
        
        # Run each test
        full_rego = validator.create_test_package(rego_code)
        
        for test_case in test_cases:
            success, opa_errors, deny_results = validator.run_opa_test(full_rego, test_case.input_data)
            
            if not success:
                error_msg = opa_errors[0] if opa_errors else 'Unknown'
                print(f"  ❌ {test_case.name}: OPA error: {error_msg}")
                # Print first few lines of rego code for debugging
                if "error" in error_msg.lower() or "invalid" in error_msg.lower():
                    print(f"     Rego code preview: {rego_code[:200]}...")
                continue
            
            has_deny = len(deny_results) > 0
            
            if test_case.should_deny:
                if not has_deny:
                    print(f"  ❌ {test_case.name}: Expected deny but got none")
                else:
                    print(f"  ✅ {test_case.name}: Deny as expected")
            else:
                if has_deny:
                    print(f"  ❌ {test_case.name}: Expected no deny but got: {deny_results[:2]}")
                else:
                    print(f"  ✅ {test_case.name}: No deny as expected")

if __name__ == "__main__":
    test_specific_cases()
