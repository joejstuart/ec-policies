#!/usr/bin/env python3
"""
Validate Rego code against natural language requirements before adding to training data.

This script:
1. Takes natural language requirement and candidate Rego code
2. Generates test cases (positive and negative)
3. Runs Rego code against test data using OPA
4. Validates output matches expectations
5. Only approves if all tests pass
"""

import json
import subprocess
import tempfile
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass


@dataclass
class TestCase:
    """A test case for validating Rego code."""
    name: str
    input_data: Dict[str, Any]
    should_deny: bool  # True if we expect a deny result, False if we expect no deny
    expected_deny_msg: Optional[str] = None  # Optional expected message


@dataclass
class ValidationResult:
    """Result of validating Rego code."""
    passed: bool
    errors: List[str]
    test_results: List[Dict[str, Any]]


class RegoValidator:
    """Validates Rego code against test cases."""
    
    def __init__(self, policy_dir: str = "../policy"):
        self.policy_dir = Path(policy_dir)
        self.temp_dir = None
    
    def extract_rego_code(self, assistant_content: str) -> str:
        """Extract Rego code from markdown code block."""
        # Look for ```rego or ``` blocks
        if "```rego" in assistant_content:
            start = assistant_content.find("```rego") + 7
            end = assistant_content.find("```", start)
            if end != -1:
                return assistant_content[start:end].strip()
        elif "```" in assistant_content:
            start = assistant_content.find("```") + 3
            end = assistant_content.find("```", start)
            if end != -1:
                return assistant_content[start:end].strip()
        # If no code block, assume entire content is Rego
        return assistant_content.strip()
    
    def create_test_package(self, rego_code: str) -> str:
        """Create a temporary Rego package for testing."""
        # Check if rego_code already has package and imports
        has_package = any(line.strip().startswith("package ") for line in rego_code.split("\n"))
        has_import = "import rego.v1" in rego_code
        
        # If it already has both, return as-is
        if has_package and has_import:
            return rego_code
        
        # Extract package name or use default
        package_name = "test_policy"
        if has_package:
            package_line = [line for line in rego_code.split("\n") if line.strip().startswith("package ")][0]
            package_name = package_line.split("package ")[1].split()[0]
        
        # Remove existing package/import lines if present
        lines = rego_code.split("\n")
        filtered_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("package ") or stripped.startswith("import "):
                continue
            filtered_lines.append(line)
        
        # Create complete package with imports
        full_code = f"""package {package_name}

import rego.v1

{chr(10).join(filtered_lines)}
"""
        return full_code
    
    def run_opa_test(self, rego_code: str, input_data: Dict[str, Any]) -> Tuple[bool, List[str], Any]:
        """
        Run Rego code with OPA and return results.
        Returns: (success, errors, deny_results)
        """
        # Extract package name
        package_name = "test_policy"
        if "package " in rego_code:
            package_line = [line for line in rego_code.split("\n") if line.strip().startswith("package ")][0]
            package_name = package_line.split("package ")[1].split()[0]
        
        # Create temporary files
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # Write Rego code
            rego_file = tmp_path / "policy.rego"
            rego_file.write_text(rego_code)
            
            # Write input data
            input_file = tmp_path / "input.json"
            input_file.write_text(json.dumps(input_data, indent=2))
            
            # Run OPA eval
            try:
                result = subprocess.run(
                    ["opa", "eval", "-d", str(rego_file), "-i", str(input_file), f"data.{package_name}.deny"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    return False, [result.stderr], []
                
                # Parse output
                output = json.loads(result.stdout)
                deny_results = output.get("result", [])
                
                # Extract actual deny values
                if deny_results and len(deny_results) > 0:
                    actual_denies = deny_results[0].get("expressions", [{}])[0].get("value", [])
                    return True, [], actual_denies
                else:
                    return True, [], []
                    
            except subprocess.TimeoutExpired:
                return False, ["OPA evaluation timed out"], []
            except json.JSONDecodeError as e:
                return False, [f"Failed to parse OPA output: {e}"], []
            except Exception as e:
                return False, [f"Error running OPA: {e}"], []
    
    def validate_test_case(self, rego_code: str, test_case: TestCase) -> Tuple[bool, List[str]]:
        """Validate a single test case."""
        errors = []
        
        # Run the Rego code
        success, opa_errors, deny_results = self.run_opa_test(rego_code, test_case.input_data)
        
        if not success:
            errors.extend(opa_errors)
            return False, errors
        
        # Check if deny results match expectations
        has_deny = len(deny_results) > 0
        
        if test_case.should_deny:
            if not has_deny:
                errors.append(f"Test '{test_case.name}': Expected deny but got none")
                return False, errors
            
            # Check expected message if provided
            if test_case.expected_deny_msg:
                deny_msgs = [str(d) for d in deny_results]
                if test_case.expected_deny_msg not in " ".join(deny_msgs):
                    errors.append(
                        f"Test '{test_case.name}': Expected message containing "
                        f"'{test_case.expected_deny_msg}' but got: {deny_msgs}"
                    )
                    return False, errors
        else:
            if has_deny:
                errors.append(
                    f"Test '{test_case.name}': Expected no deny but got: {deny_results}"
                )
                return False, errors
        
        return True, []
    
    def validate(self, rego_code: str, test_cases: List[TestCase]) -> ValidationResult:
        """Validate Rego code against all test cases."""
        errors = []
        test_results = []
        
        # Create full package code
        full_rego = self.create_test_package(rego_code)
        
        for test_case in test_cases:
            passed, test_errors = self.validate_test_case(full_rego, test_case)
            test_results.append({
                "name": test_case.name,
                "passed": passed,
                "errors": test_errors
            })
            if not passed:
                errors.extend(test_errors)
        
        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
            test_results=test_results
        )


class TestCaseGenerator:
    """Generates test cases from natural language requirements."""
    
    def generate_test_cases(self, natural_language: str, rego_code: str) -> List[TestCase]:
        """
        Generate test cases based on natural language requirement.
        This is a template - should be customized per requirement type.
        """
        test_cases = []
        
        # Example: "Verify the prefetch-dependencies task was not invoked with 'permissive' mode"
        if "prefetch-dependencies" in natural_language.lower() and "permissive" in natural_language.lower():
            # Positive test: should deny when mode is permissive
            test_cases.append(TestCase(
                name="prefetch_permissive_should_deny",
                input_data=self._create_attestation_with_task_param("prefetch-dependencies", "mode", "permissive"),
                should_deny=True,
                expected_deny_msg="permissive"
            ))
            
            # Negative test: should not deny when mode is not permissive
            test_cases.append(TestCase(
                name="prefetch_strict_should_pass",
                input_data=self._create_attestation_with_task_param("prefetch-dependencies", "mode", "strict"),
                should_deny=False
            ))
            
            # Negative test: should not deny when task doesn't exist
            test_cases.append(TestCase(
                name="other_task_should_pass",
                input_data=self._create_attestation_with_task_param("other-task", "mode", "permissive"),
                should_deny=False
            ))
        
        # Example: "Verify all tasks completed successfully"
        elif "completed successfully" in natural_language.lower() or "status" in natural_language.lower():
            # Positive test: should deny when task status is not Succeeded
            test_cases.append(TestCase(
                name="failed_task_should_deny",
                input_data=self._create_attestation_with_task_status("build", "Failed"),
                should_deny=True
            ))
            
            # Negative test: should not deny when all tasks succeeded
            test_cases.append(TestCase(
                name="succeeded_task_should_pass",
                input_data=self._create_attestation_with_task_status("build", "Succeeded"),
                should_deny=False
            ))
        
        # Add more patterns as needed...
        
        return test_cases
    
    def _create_attestation_with_task_param(self, task_name: str, param_name: str, param_value: str) -> Dict:
        """Create test attestation with a task having a specific parameter."""
        return {
            "attestations": [{
                "statement": {
                    "_type": "https://in-toto.io/Statement/v0.1",
                    "predicateType": "https://slsa.dev/provenance/v0.2",
                    "predicate": {
                        "buildType": "tekton.dev/v1/PipelineRun",
                        "buildConfig": {
                            "tasks": [{
                                "name": task_name,
                                "ref": {
                                    "name": task_name,
                                    "kind": "Task"
                                },
                                "invocation": {
                                    "parameters": {
                                        param_name: param_value
                                    }
                                }
                            }]
                        }
                    }
                }
            }]
        }
    
    def _create_attestation_with_task_status(self, task_name: str, status: str) -> Dict:
        """Create test attestation with a task having a specific status."""
        return {
            "attestations": [{
                "statement": {
                    "_type": "https://in-toto.io/Statement/v0.1",
                    "predicateType": "https://slsa.dev/provenance/v0.2",
                    "predicate": {
                        "buildType": "tekton.dev/v1/PipelineRun",
                        "buildConfig": {
                            "tasks": [{
                                "name": task_name,
                                "status": status,
                                "ref": {
                                    "name": task_name,
                                    "kind": "Task"
                                }
                            }]
                        }
                    }
                }
            }]
        }


def validate_training_example(natural_language: str, assistant_content: str) -> ValidationResult:
    """
    Validate a training example.
    
    Args:
        natural_language: The user's natural language requirement
        assistant_content: The assistant's response with Rego code
    
    Returns:
        ValidationResult with pass/fail status and errors
    """
    validator = RegoValidator()
    generator = TestCaseGenerator()
    
    # Extract Rego code
    rego_code = validator.extract_rego_code(assistant_content)
    
    # Generate test cases
    test_cases = generator.generate_test_cases(natural_language, rego_code)
    
    if not test_cases:
        return ValidationResult(
            passed=False,
            errors=[f"No test cases generated for: {natural_language}"],
            test_results=[]
        )
    
    # Validate
    return validator.validate(rego_code, test_cases)


def main():
    """CLI interface for validation."""
    if len(sys.argv) < 3:
        print("Usage: validate_rego_training.py <natural_language> <assistant_content_file>")
        print("   or: validate_rego_training.py --jsonl <training_data.jsonl>")
        sys.exit(1)
    
    if sys.argv[1] == "--jsonl":
        # Validate entire JSONL file
        jsonl_file = sys.argv[2]
        validate_jsonl_file(jsonl_file)
    else:
        # Validate single example
        natural_language = sys.argv[1]
        assistant_file = sys.argv[2]
        
        with open(assistant_file) as f:
            assistant_content = f.read()
        
        result = validate_training_example(natural_language, assistant_content)
        
        if result.passed:
            print("✅ Validation passed!")
            sys.exit(0)
        else:
            print("❌ Validation failed:")
            for error in result.errors:
                print(f"  - {error}")
            sys.exit(1)


def validate_jsonl_file(jsonl_file: str):
    """Validate all examples in a JSONL file."""
    passed = 0
    failed = 0
    
    with open(jsonl_file) as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                messages = data.get("messages", [])
                
                # Find user and assistant messages
                user_msg = None
                assistant_msg = None
                
                for msg in messages:
                    if msg.get("role") == "user":
                        user_msg = msg.get("content", "")
                    elif msg.get("role") == "assistant":
                        assistant_msg = msg.get("content", "")
                
                if not user_msg or not assistant_msg:
                    print(f"Line {line_num}: Missing user or assistant message")
                    failed += 1
                    continue
                
                result = validate_training_example(user_msg, assistant_msg)
                
                if result.passed:
                    print(f"✅ Line {line_num}: Passed")
                    passed += 1
                else:
                    print(f"❌ Line {line_num}: Failed")
                    for error in result.errors:
                        print(f"     - {error}")
                    failed += 1
                    
            except json.JSONDecodeError as e:
                print(f"Line {line_num}: Invalid JSON - {e}")
                failed += 1
    
    print(f"\nSummary: {passed} passed, {failed} failed")


if __name__ == "__main__":
    main()
