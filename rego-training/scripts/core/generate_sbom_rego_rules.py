#!/usr/bin/env python3
"""
Generate SBOM Rego rule files for each test case.

Reads sbom_data/comprehensive_test_cases.json to create
individual Rego files for each test case in the sbom_rego_rules/ directory.
"""

import json
import re
from pathlib import Path

def sanitize_filename(name: str) -> str:
    """Convert test case ID to a valid filename."""
    # Replace underscores and hyphens, make lowercase
    name = name.lower()
    # Replace special characters with underscores
    name = re.sub(r'[^a-z0-9_-]', '_', name)
    # Remove multiple consecutive underscores
    name = re.sub(r'_+', '_', name)
    # Remove leading/trailing underscores
    name = name.strip('_')
    return name

def create_rego_file(case_id: str, natural_language: str, rego_code: str, output_dir: Path):
    """Create a Rego file for a test case."""
    filename = sanitize_filename(case_id) + ".rego"
    filepath = output_dir / filename
    
    # Extract a short name for the package
    package_name = sanitize_filename(case_id)
    if len(package_name) > 50:
        package_name = package_name[:50]
    
    # Create the Rego file content
    content = f"""#
# METADATA
# title: {natural_language}
# description: >-
#   {natural_language}
# custom:
#   short_name: {case_id}
#   failure_msg: Policy validation failed
#
package {package_name}

import rego.v1

{rego_code}
"""
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    return filepath

def main():
    """Generate Rego files for all SBOM test cases.
    
    TDD Workflow:
    1. Try to read from comprehensive_test_cases.json (legacy - has rego_code)
    2. If not available, read from requirements.json + test_case_definitions.json
    3. For TDD: Rules should be generated to make tests pass (model or manual)
    """
    project_root = Path(__file__).parent.parent.parent
    
    # Try comprehensive_test_cases.json first (legacy), then requirements.json (TDD)
    comprehensive_file = project_root / "sbom_data" / "comprehensive_test_cases.json"
    requirements_file = project_root / "sbom_data" / "requirements.json"
    test_definitions_file = project_root / "sbom_data" / "test_case_definitions.json"
    
    use_legacy = comprehensive_file.exists()
    
    if use_legacy:
        print("📋 Using legacy workflow: reading rego_code from comprehensive_test_cases.json")
        with open(comprehensive_file) as f:
            data = json.load(f)
        test_cases = data.get("test_cases", {})
    else:
        print("📋 Using TDD workflow: reading from requirements.json")
        if not requirements_file.exists():
            print(f"Error: Neither {comprehensive_file} nor {requirements_file} exists")
            return
        
        with open(requirements_file) as f:
            requirements_data = json.load(f)
        test_cases = requirements_data.get("requirements", {})
        
        # For TDD, we need rego_code - this should come from model generation or manual creation
        # For now, check if comprehensive_test_cases.json exists as fallback
        print("⚠️  TDD workflow: Rego code should be generated from requirements + tests")
        print("   For now, checking if comprehensive_test_cases.json exists as fallback...")
        if comprehensive_file.exists():
            with open(comprehensive_file) as f:
                legacy_data = json.load(f)
            legacy_cases = legacy_data.get("test_cases", {})
            # Merge rego_code from legacy if available
            for case_id in test_cases:
                if case_id in legacy_cases:
                    test_cases[case_id]["rego_code"] = legacy_cases[case_id].get("rego_code")
    
    # Create output directory
    output_dir = project_root / "sbom_rego_rules"
    output_dir.mkdir(exist_ok=True)
    
    # Track statistics
    created = 0
    missing_rego = []
    
    print(f"Processing {len(test_cases)} SBOM test cases...")
    
    for case_id, test_case in test_cases.items():
        natural_language = test_case.get("natural_language", "")
        rego_code = test_case.get("rego_code")
        
        if not rego_code:
            missing_rego.append(case_id)
            if not use_legacy:
                print(f"  ⚠️  TDD: No Rego code for {case_id} - should be generated from requirements + tests")
            else:
                print(f"  WARNING: No Rego code found for {case_id}")
            continue
        
        # Create Rego file
        filepath = create_rego_file(case_id, natural_language, rego_code, output_dir)
        created += 1
        
        if created % 50 == 0:
            print(f"  Created {created} files...")
    
    print(f"\n✅ Generated {created} SBOM Rego rule files in {output_dir}/")
    if missing_rego:
        if use_legacy:
            print(f"\n⚠️  WARNING: {len(missing_rego)} test cases missing Rego code:")
            for case_id in missing_rego[:10]:
                print(f"  - {case_id}")
            if len(missing_rego) > 10:
                print(f"  ... and {len(missing_rego) - 10} more")
        else:
            print(f"\n💡 TDD: {len(missing_rego)} requirements need Rego code generation")
            print(f"   These should be generated from requirements + test_case_definitions.json")
            print(f"   Use a model or manual creation to generate rules that make tests pass")
    else:
        print("  All test cases have Rego code!")

if __name__ == "__main__":
    main()
