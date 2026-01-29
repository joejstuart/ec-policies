#!/usr/bin/env python3
"""
Generate SBOM test creation training data.

This script creates three types of training examples:
1. Requirement → Rule: Given a requirement, create a Rego rule
2. Rule → Test: Given a Rego rule, create tests for it
3. Requirement → Rule + Test: Given a requirement, create both the rule and tests

These examples help the model learn:
- How to write rules from requirements
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
        
        system_prompt = """You are an expert at writing OPA Rego test files for SBOM (Software Bill of Materials) policy rules. You understand how to create comprehensive test cases for Rego policy rules following OPA testing best practices.

## SBOM Access Pattern

SBOMs are accessed directly from `input.attestations` by checking the `predicateType`:

**For SPDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://spdx.dev/Document"
sbom := statement.predicate
```

**For CycloneDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://cyclonedx.org/bom"
sbom := statement.predicate
```

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
   - Use realistic SBOM attestation data
   - Test edge cases and boundary conditions

4. **Test Data**:
   - Use complete SBOM attestation structures with all required fields
   - Ensure test data matches the rule's validation requirements
   - Include both valid and invalid scenarios

Write comprehensive test files that provide full coverage of the Rego rule."""
        
        user_message = f"""Given the following Rego policy rule, create a complete test file for it.

**Requirement**: {natural_language}

**Rego Rule**:
```rego
package {package_name}

import rego.v1

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
- Realistic SBOM attestation data that exercises the rule's validation logic
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
    
    system_prompt = """You are an expert at writing OPA Rego policy rules and their corresponding test files for Enterprise Contract SBOM (Software Bill of Materials) validation. You understand the structure of SBOM attestations and can translate natural language policy requirements into Rego code with comprehensive tests.

**IMPORTANT**: Use pure Rego without importing any libraries from this repo. Access SBOMs directly from attestations.

## SBOM Access Pattern

SBOMs are accessed directly from `input.attestations` by checking the `predicateType`:

**For SPDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://spdx.dev/Document"
sbom := statement.predicate
```

**For CycloneDX SBOMs:**
```rego
some att in input.attestations
statement := att.statement
statement.predicateType == "https://cyclonedx.org/bom"
sbom := statement.predicate
```

## SPDX SBOM Structure

After accessing the SBOM via `sbom := statement.predicate`:
- `sbom.packages` - Array of packages in the SPDX SBOM
- `sbom.files` - Array of files in the SPDX SBOM
- `sbom.name` - SBOM document name
- `pkg.name` - Package name
- `pkg.versionInfo` - Package version
- `pkg.externalRefs` - Array of external references (PURL, CPE, etc.)

## CycloneDX SBOM Structure

After accessing the SBOM via `sbom := statement.predicate`:
- `sbom.components` - Array of components in the CycloneDX SBOM
- `comp.name` - Component name
- `comp.version` - Component version
- `comp.purl` - Package URL for the component

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
   - Use realistic SBOM attestation data
   - Test edge cases and boundary conditions

Write Rego deny rules that check the SBOM structure using pure Rego, and create comprehensive test files for each rule."""
    
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
- Realistic SBOM attestation data that exercises the rule's validation logic
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
    """Generate SBOM test creation training data."""
    project_root = Path(__file__).parent.parent.parent
    rego_dir = project_root / "sbom_rego_rules"
    output_file = project_root / "sbom_data" / "qwen3-sbom-test-creation-training.jsonl"
    
    if not rego_dir.exists():
        print(f"Error: {rego_dir} does not exist")
        return
    
    # Create data directory if it doesn't exist
    output_file.parent.mkdir(exist_ok=True)
    
    # Find all rule files (exclude test files)
    rule_files = sorted([f for f in rego_dir.glob("*.rego") if not f.name.endswith("_test.rego")])
    print(f"Processing {len(rule_files)} SBOM Rego rule files...")
    
    rule_to_test_count = 0
    requirement_to_rule_and_test_count = 0
    skipped_count = 0
    
    with open(output_file, 'w') as out:
        for rule_file in rule_files:
            try:
                # Find corresponding test file
                test_file = rego_dir / f"{rule_file.stem}_test.rego"
                
                if not test_file.exists():
                    skipped_count += 1
                    continue
                
                # Read rule file
                with open(rule_file) as f:
                    rego_content = f.read()
                
                # Read test file
                with open(test_file) as f:
                    test_content = f.read()
                
                # Extract metadata
                metadata = extract_metadata(rego_content)
                natural_language = metadata.get('title', '')
                
                if not natural_language:
                    skipped_count += 1
                    continue
                
                # Extract code
                rego_code = extract_rego_code(rego_content)
                test_code = extract_test_code(test_content)
                
                if not rego_code or not test_code:
                    skipped_count += 1
                    continue
                
                # Extract package name
                package_match = re.search(r'^package\s+(\w+)', rego_content, re.MULTILINE)
                if not package_match:
                    skipped_count += 1
                    continue
                package_name = package_match.group(1)
                
                # Create Rule → Test example
                rule_to_test = create_rule_to_test_example(rule_file, test_file, natural_language)
                if rule_to_test:
                    out.write(json.dumps(rule_to_test) + '\n')
                    rule_to_test_count += 1
                
                # Create Requirement → Rule + Test example
                req_to_rule_test = create_requirement_to_rule_and_test_example(
                    natural_language, rego_code, test_code, package_name
                )
                if req_to_rule_test:
                    out.write(json.dumps(req_to_rule_test) + '\n')
                    requirement_to_rule_and_test_count += 1
                
                if (rule_to_test_count + requirement_to_rule_and_test_count) % 50 == 0:
                    print(f"  Processed {(rule_to_test_count + requirement_to_rule_and_test_count) // 2} rule/test pairs...")
                    
            except Exception as e:
                print(f"  ❌ Error processing {rule_file.name}: {e}")
                skipped_count += 1
    
    print(f"\n✅ Generated SBOM test creation training data:")
    print(f"   Rule → Test examples: {rule_to_test_count}")
    print(f"   Requirement → Rule + Test examples: {requirement_to_rule_and_test_count}")
    print(f"   Total examples: {rule_to_test_count + requirement_to_rule_and_test_count}")
    print(f"   Skipped: {skipped_count}")
    print(f"   Output: {output_file}")

if __name__ == "__main__":
    main()
