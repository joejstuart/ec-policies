#!/usr/bin/env python3
"""
Generate Rego rule files for each test case.

Reads test_case_definitions.json and comprehensive_test_cases.json to create
individual Rego files for each test case in the rego_rules/ directory.
"""

import json
import os
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
    package_name = sanitize_filename(case_id).replace('_', '_')
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
    """Generate Rego files for all test cases."""
    # Load test case definitions
    with open("../data/test_case_definitions.json") as f:
        test_definitions = json.load(f)
    
    # Load comprehensive test cases to get Rego code
    with open("../data/comprehensive_test_cases.json") as f:
        comprehensive = json.load(f)
    
    # Create output directory
    output_dir = Path("rego_rules")
    output_dir.mkdir(exist_ok=True)
    
    # Track statistics
    created = 0
    missing_rego = []
    
    # Process each test case
    test_cases = test_definitions.get("test_cases", {})
    comprehensive_cases = comprehensive.get("test_cases", {})
    
    print(f"Processing {len(test_cases)} test cases...")
    
    for case_id, test_case in test_cases.items():
        natural_language = test_case.get("natural_language", "")
        
        # Try to find Rego code in comprehensive test cases
        rego_code = None
        if case_id in comprehensive_cases:
            rego_code = comprehensive_cases[case_id].get("rego_code")
        
        if not rego_code:
            # Try to find by natural language match
            for comp_id, comp_case in comprehensive_cases.items():
                if comp_case.get("natural_language", "").lower() == natural_language.lower():
                    rego_code = comp_case.get("rego_code")
                    break
        
        if not rego_code:
            missing_rego.append(case_id)
            print(f"  WARNING: No Rego code found for {case_id}")
            continue
        
        # Create Rego file
        filepath = create_rego_file(case_id, natural_language, rego_code, output_dir)
        created += 1
        
        if created % 50 == 0:
            print(f"  Created {created} files...")
    
    print(f"\nGenerated {created} Rego rule files in {output_dir}/")
    if missing_rego:
        print(f"\nWARNING: {len(missing_rego)} test cases missing Rego code:")
        for case_id in missing_rego[:10]:
            print(f"  - {case_id}")
        if len(missing_rego) > 10:
            print(f"  ... and {len(missing_rego) - 10} more")

if __name__ == "__main__":
    main()
