#!/usr/bin/env python3
"""
Validate all Rego rules against test_case_definitions.json.
"""

import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from validate_rego_training import RegoValidator, TestCase, ValidationResult

def load_test_case_definitions():
    """Load test case definitions from JSON file."""
    with open("../data/test_case_definitions.json") as f:
        return json.load(f)

def load_rego_rule(case_id: str) -> str:
    """Load Rego rule for a test case."""
    rego_file = Path("rego_rules") / f"{case_id}.rego"
    if not rego_file.exists():
        return None
    return rego_file.read_text()

def convert_test_to_testcase(test: dict) -> TestCase:
    """Convert test dict to TestCase object."""
    return TestCase(
        name=test["name"],
        input_data=test["input"],
        should_deny=test.get("should_deny", False),
        expected_deny_msg=test.get("expected_msg_contains")
    )

def main():
    """Validate all Rego rules."""
    test_definitions = load_test_case_definitions()
    validator = RegoValidator()
    
    passed = 0
    failed = 0
    failures = []
    
    for case_id, test_case in test_definitions["test_cases"].items():
        rego_code = load_rego_rule(case_id)
        if not rego_code:
            print(f"⚠️  {case_id}: No Rego file found")
            failed += 1
            failures.append((case_id, ["No Rego file found"]))
            continue
        
        # Convert tests to TestCase objects
        test_cases = [convert_test_to_testcase(t) for t in test_case["tests"]]
        
        # Validate
        result = validator.validate(rego_code, test_cases)
        
        if result.passed:
            print(f"✅ {case_id}")
            passed += 1
        else:
            print(f"❌ {case_id}: {len(result.errors)} errors")
            for test_result in result.test_results:
                if not test_result["passed"]:
                    print(f"   Test '{test_result['name']}': {test_result['errors']}")
            failed += 1
            failures.append((case_id, result.errors))
    
    print(f"\n{'='*60}")
    print(f"Summary: {passed} passed, {failed} failed")
    print(f"{'='*60}")
    
    if failures:
        print("\nFailures:")
        for case_id, errors in failures[:20]:  # Show first 20
            print(f"\n{case_id}:")
            for error in errors[:3]:  # Show first 3 errors per case
                print(f"  - {error}")
        if len(failures) > 20:
            print(f"\n... and {len(failures) - 20} more failures")

if __name__ == "__main__":
    main()
