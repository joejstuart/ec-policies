#!/usr/bin/env python3
"""
Generate SBOM validation test data using a simpler approach.

Instead of complex regex pattern matching on Rego code, this uses:
1. Natural language descriptions to understand what's being checked
2. keys_used to know which fields to modify
3. Simple heuristics based on common patterns
"""

import json
from typing import Dict, List
from pathlib import Path

def create_base_spdx_attestation() -> Dict:
    """Create a base SPDX SBOM attestation structure."""
    return {
        "statement": {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://spdx.dev/Document",
            "predicate": {
                "SPDXID": "SPDXRef-DOCUMENT",
                "spdxVersion": "SPDX-2.3",
                "name": "test-image@sha256:abc123",
                "documentNamespace": "https://example.com/spdxdocs/test-image",
                "dataLicense": "CC0-1.0",
                "creationInfo": {
                    "created": "2024-01-01T00:00:00Z",
                    "creators": ["Organization: Test Org", "Tool: test-tool-1.0"],
                    "licenseListVersion": "3.25"
                },
                "packages": [{
                    "SPDXID": "SPDXRef-Package-test-1",
                    "name": "test-package",
                    "versionInfo": "1.0.0",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "supplier": "Organization: Test Supplier",
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": "a" * 64},
                        {"algorithm": "SHA1", "checksumValue": "b" * 40}
                    ],
                    "externalRefs": [{
                        "referenceCategory": "PACKAGE_MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:rpm/test-package@1.0.0"
                    }]
                }],
                "files": []
            }
        }
    }

def create_base_cyclonedx_attestation() -> Dict:
    """Create a base CycloneDX SBOM attestation structure."""
    return {
        "statement": {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://cyclonedx.org/bom",
            "predicate": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789012",
                "metadata": {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "tools": [{
                        "vendor": "Test Vendor",
                        "name": "test-tool",
                        "version": "1.0.0"
                    }],
                    "component": {
                        "type": "container",
                        "name": "test-image",
                        "bom-ref": "test-image-ref"
                    }
                },
                "components": [{
                    "type": "library",
                    "name": "test-component",
                    "version": "1.0.0",
                    "bom-ref": "test-component-ref",
                    "purl": "pkg:rpm/test-component@1.0.0",
                    "licenses": [{"license": {"name": "MIT"}}]
                }]
            }
        }
    }

def generate_simple_tests(test_case: Dict, case_id: str) -> List[Dict]:
    """Generate validation tests using a simpler approach.
    
    Strategy:
    1. Use natural language to understand intent
    2. Use keys_used to know which fields to modify
    3. Generate positive (should deny) and negative (should pass) tests
    """
    natural_language = test_case["natural_language"]
    keys_used = test_case.get("keys_used", [])
    nl_lower = natural_language.lower()
    
    # Determine SBOM type
    is_spdx = "spdx" in case_id.lower() or any("spdx" in str(k).lower() for k in keys_used)
    is_cyclonedx = "cyclonedx" in case_id.lower() or any("cyclonedx" in str(k).lower() for k in keys_used)
    
    tests = []
    
    # Strategy: Generate tests based on natural language patterns
    # This is much simpler than parsing Rego code
    
    # Pattern: "contains packages" or "has packages"
    if ("contains packages" in nl_lower or "has packages" in nl_lower) and is_spdx:
        pos_test = create_base_spdx_attestation()
        pos_test["statement"]["predicate"]["packages"] = []
        tests.append({
            "name": "should_deny_when_no_packages",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        tests.append({
            "name": "should_pass_when_has_packages",
            "input": {"attestations": [create_base_spdx_attestation()]},
            "should_deny": False
        })
        return tests
    
    # Pattern: "contains components" or "has components"
    if ("contains components" in nl_lower or "has components" in nl_lower) and is_cyclonedx:
        pos_test = create_base_cyclonedx_attestation()
        pos_test["statement"]["predicate"]["components"] = []
        tests.append({
            "name": "should_deny_when_no_components",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        tests.append({
            "name": "should_pass_when_has_components",
            "input": {"attestations": [create_base_cyclonedx_attestation()]},
            "should_deny": False
        })
        return tests
    
    # Pattern: "have a <field>" or "have <field>"
    # Extract field name from natural language and keys_used
    if ("have a " in nl_lower or "have " in nl_lower) and is_spdx:
        # Try to extract field name from keys_used
        field_path = None
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str or "package" in key_str.lower():
                # Extract field name (e.g., "pkg.supplier" -> "supplier")
                parts = key_str.split(".")
                if len(parts) > 1:
                    field_name = parts[-1]
                    field_path = ["statement", "predicate", "packages", 0, field_name]
                    break
        
        if field_path:
            # Positive test: missing field
            pos_test = create_base_spdx_attestation()
            pkg = pos_test["statement"]["predicate"]["packages"][0]
            if field_path[-1] in pkg:
                del pkg[field_path[-1]]
            tests.append({
                "name": f"should_deny_when_package_missing_{field_path[-1].lower()}",
                "input": {"attestations": [pos_test]},
                "should_deny": True
            })
            
            # Negative test: field present
            tests.append({
                "name": f"should_pass_when_package_has_{field_path[-1].lower()}",
                "input": {"attestations": [create_base_spdx_attestation()]},
                "should_deny": False
            })
            return tests
    
    # Default: Generate basic positive/negative tests
    # Positive: remove a field or set to invalid value
    # Negative: use valid base structure
    if is_spdx:
        pos_test = create_base_spdx_attestation()
        # Remove a common field to trigger violation
        if pos_test["statement"]["predicate"]["packages"]:
            pkg = pos_test["statement"]["predicate"]["packages"][0]
            if "name" in pkg:
                del pkg["name"]
        tests.append({
            "name": "should_deny_when_condition_violated",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        tests.append({
            "name": "should_pass_when_condition_met",
            "input": {"attestations": [create_base_spdx_attestation()]},
            "should_deny": False
        })
    elif is_cyclonedx:
        pos_test = create_base_cyclonedx_attestation()
        if pos_test["statement"]["predicate"]["components"]:
            comp = pos_test["statement"]["predicate"]["components"][0]
            if "name" in comp:
                del comp["name"]
        tests.append({
            "name": "should_deny_when_condition_violated",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        tests.append({
            "name": "should_pass_when_condition_met",
            "input": {"attestations": [create_base_cyclonedx_attestation()]},
            "should_deny": False
        })
    
    return tests

def main():
    """Generate validation test definitions."""
    input_file = Path("sbom_data/comprehensive_test_cases.json")
    output_file = Path("sbom_data/test_case_definitions.json")
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    test_definitions = {
        "metadata": {
            "source": "comprehensive_test_cases.json",
            "generated_by": "generate_sbom_validation_tests_simple.py"
        },
        "test_cases": {}
    }
    
    generated = 0
    for case_id, test_case in data["test_cases"].items():
        try:
            tests = generate_simple_tests(test_case, case_id)
            if tests:
                test_definitions["test_cases"][case_id] = {
                    "natural_language": test_case["natural_language"],
                    "tests": tests
                }
                generated += 1
        except Exception as e:
            print(f"⚠️  Error generating tests for {case_id}: {e}")
    
    with open(output_file, 'w') as f:
        json.dump(test_definitions, f, indent=2)
    
    print(f"✅ Generated validation tests for {generated} test cases")
    print(f"📁 Output: {output_file}")

if __name__ == "__main__":
    main()
