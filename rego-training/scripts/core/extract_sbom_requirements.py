#!/usr/bin/env python3
"""
Extract requirements from comprehensive_test_cases.json.

Removes rego_code field, keeping only natural_language, keys_used, and type.
This creates a clean requirements file for TDD workflow.
"""

import json
from pathlib import Path

def main():
    """Extract requirements from comprehensive_test_cases.json."""
    project_root = Path(__file__).parent.parent.parent
    
    # Load comprehensive test cases
    comprehensive_file = project_root / "sbom_data" / "comprehensive_test_cases.json"
    requirements_file = project_root / "sbom_data" / "requirements.json"
    
    if not comprehensive_file.exists():
        print(f"Error: {comprehensive_file} does not exist")
        return
    
    with open(comprehensive_file, 'r') as f:
        data = json.load(f)
    
    # Extract requirements (remove rego_code)
    requirements = {
        "metadata": {
            "source": "comprehensive_test_cases.json",
            "extracted_by": "extract_sbom_requirements.py",
            "description": "SBOM policy requirements for TDD workflow. Contains only natural language descriptions, keys_used, and type. No implementation (rego_code).",
            "total_requirements": 0
        },
        "requirements": {}
    }
    
    test_cases = data.get("test_cases", {})
    for case_id, test_case in test_cases.items():
        requirements["requirements"][case_id] = {
            "natural_language": test_case.get("natural_language", ""),
            "keys_used": test_case.get("keys_used", []),
            "type": test_case.get("type", "compound")
        }
    
    requirements["metadata"]["total_requirements"] = len(requirements["requirements"])
    
    # Write requirements file
    with open(requirements_file, 'w') as f:
        json.dump(requirements, f, indent=2)
    
    print(f"✅ Extracted {len(requirements['requirements'])} requirements")
    print(f"📁 Output: {requirements_file}")
    print(f"\nRequirements contain:")
    print(f"  - natural_language: ✅")
    print(f"  - keys_used: ✅")
    print(f"  - type: ✅")
    print(f"  - rego_code: ❌ (removed for TDD workflow)")

if __name__ == "__main__":
    main()
