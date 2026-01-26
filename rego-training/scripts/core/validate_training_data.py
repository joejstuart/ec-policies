#!/usr/bin/env python3
"""
Validate training data quality:
- Check role correctness (system, user, assistant)
- Verify assistant responses match user requests
- Ensure system prompts are relevant
- Check for common issues
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict


def extract_rego_code(text: str) -> str:
    """Extract Rego code blocks from text."""
    matches = re.findall(r'```rego\n(.*?)\n```', text, re.DOTALL)
    return matches[0] if matches else ""


def check_roles(messages: List[Dict]) -> Tuple[bool, List[str]]:
    """Check if roles are correct."""
    issues = []
    
    if not messages:
        return False, ["No messages found"]
    
    # First message should be system
    if messages[0]["role"] != "system":
        issues.append("First message should be 'system', got '{}'".format(messages[0]["role"]))
    
    # Second message should be user
    if len(messages) > 1 and messages[1]["role"] != "user":
        issues.append("Second message should be 'user', got '{}'".format(messages[1]["role"]))
    
    # Last message should be assistant
    if len(messages) > 2 and messages[-1]["role"] != "assistant":
        issues.append("Last message should be 'assistant', got '{}'".format(messages[-1]["role"]))
    
    # Check for invalid roles
    valid_roles = {"system", "user", "assistant"}
    for i, msg in enumerate(messages):
        if msg["role"] not in valid_roles:
            issues.append("Message {} has invalid role: '{}'".format(i, msg["role"]))
    
    return len(issues) == 0, issues


def check_system_relevance(system_content: str, user_content: str, assistant_content: str) -> Tuple[bool, List[str]]:
    """Check if system prompt is relevant to the task."""
    issues = []
    
    # Check if system mentions Rego/OPA
    if "rego" not in system_content.lower() and "opa" not in system_content.lower():
        issues.append("System prompt doesn't mention Rego/OPA")
    
    # Check if system mentions testing (for test creation examples)
    is_test_creation = "test" in user_content.lower() or "test" in assistant_content.lower()
    if is_test_creation and "test" not in system_content.lower():
        issues.append("System prompt should mention testing for test creation examples")
    
    # Check if system mentions Enterprise Contract/attestation
    if "attestation" in user_content.lower() or "attestation" in assistant_content.lower():
        if "attestation" not in system_content.lower():
            issues.append("System prompt should mention attestations when task involves them")
    
    return len(issues) == 0, issues


def check_assistant_implements_request(user_content: str, assistant_content: str) -> Tuple[bool, List[str]]:
    """Check if assistant correctly implements what user asks for."""
    issues = []
    
    # Check for rule generation requests
    if "rego" in user_content.lower() or "rule" in user_content.lower():
        if "```rego" not in assistant_content:
            issues.append("User asks for Rego rule but assistant doesn't provide code block")
    
    # Check for test creation requests
    if "test" in user_content.lower() and ("create" in user_content.lower() or "write" in user_content.lower()):
        if "```rego" not in assistant_content or "_test" not in assistant_content:
            issues.append("User asks for test file but assistant doesn't provide test code")
    
    # Check for package name consistency
    package_match = re.search(r'package\s+(\w+)', user_content, re.IGNORECASE)
    if package_match:
        expected_package = package_match.group(1)
        if expected_package not in assistant_content:
            issues.append("User mentions package '{}' but assistant doesn't use it".format(expected_package))
    
    # Check if assistant provides complete solution
    if "complete" in user_content.lower() or "comprehensive" in user_content.lower():
        rego_blocks = re.findall(r'```rego\n.*?\n```', assistant_content, re.DOTALL)
        if len(rego_blocks) < 1:
            issues.append("User asks for complete solution but assistant provides incomplete code")
    
    # Check for both rule and test in requirement-to-rule-and-test examples
    # Only flag if user explicitly asks for both (not just "both" in requirement text)
    user_lower = user_content.lower()
    asks_for_both = (
        ("rule" in user_lower and "test" in user_lower) and
        ("both" in user_lower or "along with" in user_lower or "and a" in user_lower) and
        ("create" in user_lower or "write" in user_lower or "generate" in user_lower) and
        ("I need" in user_content or "Create:" in user_content or "along with" in user_content)
    )
    if asks_for_both:
        rego_blocks = re.findall(r'```rego\n.*?\n```', assistant_content, re.DOTALL)
        if len(rego_blocks) < 2:
            issues.append("User asks for both rule and test but assistant doesn't provide both")
    
    return len(issues) == 0, issues


def check_code_quality(assistant_content: str) -> Tuple[bool, List[str]]:
    """Check code quality in assistant responses."""
    issues = []
    
    rego_code = extract_rego_code(assistant_content)
    if not rego_code:
        return True, []  # No code to check
    
    # Check for package declaration (but allow rule generation to just show deny rule)
    # Only require package if it's a full file (has imports or is a test file)
    is_full_file = "import " in rego_code or "_test" in assistant_content
    if is_full_file and "package " not in rego_code:
        issues.append("Rego code missing package declaration")
    
    # Check for deny rule in rule examples
    if "deny" not in rego_code and "_test" not in rego_code:
        issues.append("Rego code missing deny rule (and doesn't appear to be a test file)")
    
    # Check for import rego.v1 in test files (only if it's actually a test file)
    is_test_file = (
        ("_test" in assistant_content and "package" in rego_code and "_test" in re.search(r'package\s+(\w+)', rego_code).group(1) if re.search(r'package\s+(\w+)', rego_code) else False) or
        ("test_" in rego_code and "with input as" in rego_code)
    )
    if is_test_file:
        if "import rego.v1" not in rego_code:
            issues.append("Test file missing 'import rego.v1'")
        if not re.search(r'import\s+data\.\w+', rego_code):
            issues.append("Test file missing 'import data.{package}'")
    
    # Check for proper test structure
    if "test_" in rego_code:
        if "with input as" not in rego_code:
            issues.append("Test code missing 'with input as' for test data")
        if "count(" not in rego_code:
            issues.append("Test code missing count() check for deny results")
    
    return len(issues) == 0, issues


def validate_example(example: Dict, index: int) -> Dict:
    """Validate a single training example."""
    result = {
        "index": index,
        "valid": True,
        "issues": [],
        "type": "unknown"
    }
    
    messages = example.get("messages", [])
    
    if not messages:
        result["valid"] = False
        result["issues"].append("No messages found")
        return result
    
    # Extract content
    system_content = messages[0]["content"] if messages[0]["role"] == "system" else ""
    user_content = messages[1]["content"] if len(messages) > 1 and messages[1]["role"] == "user" else ""
    assistant_content = messages[-1]["content"] if messages[-1]["role"] == "assistant" else ""
    
    # Determine type
    if "test" in user_content.lower() and "rule" in user_content.lower() and "both" in user_content.lower():
        result["type"] = "requirement-to-rule-and-test"
    elif "test" in user_content.lower() and ("create" in user_content.lower() or "write" in user_content.lower()):
        result["type"] = "rule-to-test"
    else:
        result["type"] = "rule-generation"
    
    # Check roles
    roles_ok, role_issues = check_roles(messages)
    if not roles_ok:
        result["valid"] = False
        result["issues"].extend(role_issues)
    
    # Check system relevance
    if system_content:
        sys_ok, sys_issues = check_system_relevance(system_content, user_content, assistant_content)
        if not sys_ok:
            result["issues"].extend(sys_issues)
    
    # Check assistant implementation
    if user_content and assistant_content:
        impl_ok, impl_issues = check_assistant_implements_request(user_content, assistant_content)
        if not impl_ok:
            result["valid"] = False
            result["issues"].extend(impl_issues)
    
    # Check code quality
    if assistant_content:
        code_ok, code_issues = check_code_quality(assistant_content)
        if not code_ok:
            result["issues"].extend(code_issues)
    
    return result


def main():
    training_file = Path("data/qwen3-complete-training.jsonl")
    
    if not training_file.exists():
        print(f"❌ Error: {training_file} does not exist")
        return 1
    
    print("=" * 70)
    print("Validating Training Data")
    print("=" * 70)
    print(f"\n📖 Reading {training_file}...")
    
    examples = []
    with open(training_file, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if line.strip():
                try:
                    example = json.loads(line)
                    examples.append((line_num, example))
                except json.JSONDecodeError as e:
                    print(f"  ❌ Line {line_num}: JSON decode error: {e}")
    
    print(f"   Found {len(examples)} examples\n")
    
    # Validate each example
    results = []
    for line_num, example in examples:
        result = validate_example(example, line_num)
        results.append(result)
    
    # Summary statistics
    valid_count = sum(1 for r in results if r["valid"])
    invalid_count = len(results) - valid_count
    
    type_counts = defaultdict(int)
    for r in results:
        type_counts[r["type"]] += 1
    
    print("=" * 70)
    print("Validation Summary")
    print("=" * 70)
    print(f"\n✅ Valid examples: {valid_count}/{len(results)}")
    print(f"❌ Invalid examples: {invalid_count}/{len(results)}")
    print(f"\n📊 Example types:")
    for ex_type, count in sorted(type_counts.items()):
        print(f"   {ex_type}: {count}")
    
    # Show issues
    all_issues = defaultdict(list)
    for r in results:
        for issue in r["issues"]:
            all_issues[issue].append(r["index"])
    
    if all_issues:
        print(f"\n⚠️  Issues found:")
        for issue, indices in sorted(all_issues.items()):
            count = len(indices)
            sample = sorted(indices)[:5]
            print(f"   {issue} ({count} examples)")
            if count <= 10:
                print(f"      Examples: {sample}")
            else:
                print(f"      Sample: {sample} ... ({count - 5} more)")
    
    # Show invalid examples
    invalid_examples = [r for r in results if not r["valid"]]
    if invalid_examples:
        print(f"\n❌ Invalid examples (first 10):")
        for r in invalid_examples[:10]:
            print(f"   Line {r['index']}: {', '.join(r['issues'][:3])}")
    
    # Detailed report for first few examples with issues
    print(f"\n📋 Detailed report (first 5 examples with issues):")
    shown = 0
    for r in results:
        if r["issues"] and shown < 5:
            print(f"\n   Example {r['index']} ({r['type']}):")
            for issue in r["issues"][:5]:
                print(f"      - {issue}")
            shown += 1
    
    return 0 if invalid_count == 0 else 1


if __name__ == "__main__":
    exit(main())
