#!/usr/bin/env python3
"""
Generate SBOM validation test data for each test case.

This script generates validation test data for each SBOM test case, creating:
- Positive tests (should_deny: true) - when the condition is violated
- Negative tests (should_deny: false) - when the condition is met
"""

import json
import re
from typing import Dict, List, Any
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
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-test-1",
                        "name": "test-package",
                        "versionInfo": "1.0.0",
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: Test Supplier",
                        "checksums": [
                            {
                                "algorithm": "SHA256",
                                "checksumValue": "a" * 64
                            },
                            {
                                "algorithm": "SHA1",
                                "checksumValue": "b" * 40
                            }
                        ],
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE_MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:rpm/test-package@1.0.0"
                            }
                        ]
                    }
                ],
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
                    "tools": [
                        {
                            "vendor": "Test Vendor",
                            "name": "test-tool",
                            "version": "1.0.0"
                        }
                    ],
                    "component": {
                        "type": "container",
                        "name": "test-image",
                        "bom-ref": "test-image-ref"
                    }
                },
                "components": [
                    {
                        "type": "library",
                        "name": "test-component",
                        "version": "1.0.0",
                        "bom-ref": "test-component-ref",
                        "purl": "pkg:rpm/test-component@1.0.0",
                        "licenses": [
                            {
                                "license": {
                                    "name": "MIT"
                                }
                            }
                        ]
                    }
                ]
            }
        }
    }

def generate_sbom_validation_tests(test_case: Dict, case_id: str) -> List[Dict]:
    """Generate validation tests for an SBOM test case.
    
    Uses the rego_code from test_case to understand what the rule checks,
    then generates test data that properly violates or satisfies the condition.
    """
    natural_language = test_case["natural_language"]
    rego_code = test_case.get("rego_code", "")
    keys_used = test_case.get("keys_used", [])
    test_type = test_case.get("type", "compound")
    
    tests = []
    nl_lower = natural_language.lower()
    keys_str = str(keys_used)
    
    # Determine SBOM type
    is_spdx = "spdx" in case_id.lower() or "spdx" in keys_str
    is_cyclonedx = "cyclonedx" in case_id.lower() or "cyclonedx" in keys_str
    
    # Pattern 1: Check if SBOM contains packages/components
    # Only match if it's EXACTLY about containing packages, not about package properties
    if (nl_lower == "verify the spdx sbom contains packages." or 
        nl_lower == "verify the spdx sbom has packages.") and is_spdx:
        # Positive test: no packages
        pos_test = create_base_spdx_attestation()
        pos_test["statement"]["predicate"]["packages"] = []
        tests.append({
            "name": "should_deny_when_no_packages",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        # Negative test: has packages
        neg_test = create_base_spdx_attestation()
        tests.append({
            "name": "should_pass_when_has_packages",
            "input": {"attestations": [neg_test]},
            "should_deny": False
        })
        return tests
    
    if ("contains components" in nl_lower or "has components" in nl_lower) and is_cyclonedx:
        # Positive test: no components
        pos_test = create_base_cyclonedx_attestation()
        pos_test["statement"]["predicate"]["components"] = []
        tests.append({
            "name": "should_deny_when_no_components",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        # Negative test: has components
        neg_test = create_base_cyclonedx_attestation()
        tests.append({
            "name": "should_pass_when_has_components",
            "input": {"attestations": [neg_test]},
            "should_deny": False
        })
        return tests
    
    # Pattern 2: Check SPDXID format
    if "spdxid" in nl_lower and "format" in nl_lower and is_spdx:
        # Positive test: invalid SPDXID format
        pos_test = create_base_spdx_attestation()
        if "package" in nl_lower:
            pos_test["statement"]["predicate"]["packages"][0]["SPDXID"] = "InvalidID"
        else:
            pos_test["statement"]["predicate"]["SPDXID"] = "InvalidID"
        tests.append({
            "name": "should_deny_when_invalid_spdxid_format",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        # Negative test: valid SPDXID format
        neg_test = create_base_spdx_attestation()
        tests.append({
            "name": "should_pass_when_valid_spdxid_format",
            "input": {"attestations": [neg_test]},
            "should_deny": False
        })
        return tests
    
    # IMPORTANT: Check Rego code patterns BEFORE natural language patterns
    # This ensures we match based on actual code logic, not just NL description
    
    # Analyze Rego code to understand what it's checking
    # IMPORTANT: Check uniqueness patterns FIRST (before empty string or other patterns)
    if rego_code:
        # Check for uniqueness patterns FIRST - count(set) != count(list) means duplicates exist
        uniqueness_pattern = re.search(r'count\(([^)]+)\)\s*!=\s*count\(([^)]+)\)', rego_code)
        if uniqueness_pattern:
            set_var = uniqueness_pattern.group(1).strip()
            list_var = uniqueness_pattern.group(2).strip()
            
            # Check for file SPDXID uniqueness: file_ids := {file.SPDXID | ...}; count(file_ids) != count(sbom.files)
            if ("file" in set_var.lower() or "id" in set_var.lower()) and "files" in list_var.lower() and is_spdx:
                if "file.spdxid" in rego_code.lower():
                    # Positive test: duplicate file SPDXIDs
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["files"] = [
                        {"SPDXID": "SPDXRef-File-test-1", "fileName": "file1.txt"},
                        {"SPDXID": "SPDXRef-File-test-1", "fileName": "file2.txt"}  # Duplicate SPDXID
                    ]
                    tests.append({
                        "name": "should_deny_when_duplicate_file_spdxids",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: unique file SPDXIDs
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["files"] = [
                        {"SPDXID": "SPDXRef-File-test-1", "fileName": "file1.txt"},
                        {"SPDXID": "SPDXRef-File-test-2", "fileName": "file2.txt"}  # Unique SPDXIDs
                    ]
                    tests.append({
                        "name": "should_pass_when_unique_file_spdxids",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
            
            # Check for checksum algorithm uniqueness: chk_algorithms := {chk.algorithm | ...}; count(chk_algorithms) != count(file.checksums)
            if ("chk" in set_var.lower() or "algorithm" in set_var.lower()) and "checksums" in list_var.lower() and is_spdx:
                if "chk.algorithm" in rego_code.lower():
                    # Check if it's for files or packages
                    if "file.checksums" in rego_code.lower() or "some file" in rego_code.lower():
                        # File checksums
                        pos_test = create_base_spdx_attestation()
                        pos_test["statement"]["predicate"]["files"] = [{
                            "SPDXID": "SPDXRef-File-test-1",
                            "fileName": "test.txt",
                            "checksums": [
                                {"algorithm": "SHA256", "checksumValue": "a" * 64},
                                {"algorithm": "SHA256", "checksumValue": "b" * 64}  # Duplicate algorithm
                            ]
                        }]
                        tests.append({
                            "name": "should_deny_when_duplicate_checksum_algorithms",
                            "input": {"attestations": [pos_test]},
                            "should_deny": True
                        })
                        
                        neg_test = create_base_spdx_attestation()
                        neg_test["statement"]["predicate"]["files"] = [{
                            "SPDXID": "SPDXRef-File-test-1",
                            "fileName": "test.txt",
                            "checksums": [
                                {"algorithm": "SHA256", "checksumValue": "a" * 64},
                                {"algorithm": "SHA1", "checksumValue": "b" * 40}  # Unique algorithms
                            ]
                        }]
                        tests.append({
                            "name": "should_pass_when_unique_checksum_algorithms",
                            "input": {"attestations": [neg_test]},
                            "should_deny": False
                        })
                        return tests
                    elif "pkg.checksums" in rego_code.lower() or ("some pkg" in rego_code.lower() and "pkg.checksums" in rego_code):
                        # Package checksums
                        pos_test = create_base_spdx_attestation()
                        pos_test["statement"]["predicate"]["packages"][0]["checksums"] = [
                            {"algorithm": "SHA256", "checksumValue": "a" * 64},
                            {"algorithm": "SHA256", "checksumValue": "b" * 64}  # Duplicate algorithm
                        ]
                        tests.append({
                            "name": "should_deny_when_duplicate_checksum_algorithms",
                            "input": {"attestations": [pos_test]},
                            "should_deny": True
                        })
                        
                        neg_test = create_base_spdx_attestation()
                        neg_test["statement"]["predicate"]["packages"][0]["checksums"] = [
                            {"algorithm": "SHA256", "checksumValue": "a" * 64},
                            {"algorithm": "SHA1", "checksumValue": "b" * 40}  # Unique algorithms
                        ]
                        tests.append({
                            "name": "should_pass_when_unique_checksum_algorithms",
                            "input": {"attestations": [neg_test]},
                            "should_deny": False
                        })
                        return tests
        
        # Check for "== \"\"" pattern - means field is empty string
        empty_string_pattern = re.search(r'(\w+)\.(\w+)\s*==\s*""', rego_code)
        if empty_string_pattern:
            obj_type = empty_string_pattern.group(1)
            field_name = empty_string_pattern.group(2)
            
            if is_spdx and obj_type == "file":
                # Positive test: empty field in file
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    field_name: ""  # Empty string
                }]
                tests.append({
                    "name": f"should_deny_when_file_{field_name.lower()}_empty",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: non-empty field
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    field_name: "test.txt"  # Non-empty
                }]
                tests.append({
                    "name": f"should_pass_when_file_{field_name.lower()}_non_empty",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "pkg.field == \"value\"" or "comp.field == \"value\"" pattern - means field equals specific value (should deny)
        # Only match pkg, comp, file, ref, chk, rel - not statement, sbom, att
        equals_value_pattern = re.search(r'(pkg|comp|file|ref|chk|rel)\.(\w+)\s*==\s*"([^"]+)"', rego_code)
        if equals_value_pattern and equals_value_pattern.group(3) != "":  # Not empty string
            obj_type = equals_value_pattern.group(1)
            field_name = equals_value_pattern.group(2)
            forbidden_value = equals_value_pattern.group(3)
            
            if is_spdx and obj_type == "pkg":
                # Positive test: field equals forbidden value
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = forbidden_value
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_equals_{forbidden_value.lower().replace('(', '').replace(')', '').replace(' ', '_').replace('-', '_')}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field has different value
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_not_equals_{forbidden_value.lower().replace('(', '').replace(')', '').replace(' ', '_').replace('-', '_')}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "not startswith()" patterns FIRST - means field does NOT start with prefix
        not_startswith_pattern = re.search(r'not\s+startswith\((\w+)\.(\w+),\s*"([^"]+)"\)', rego_code)
        if not_startswith_pattern:
            obj_type = not_startswith_pattern.group(1)
            field_name = not_startswith_pattern.group(2)
            required_prefix = not_startswith_pattern.group(3)
            
            if is_spdx and obj_type == "sbom":
                # Positive test: does NOT start with required prefix
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"][field_name] = "invalid-value"  # Doesn't start with "http"
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_not_starts_with_{required_prefix.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: starts with required prefix
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"][field_name] = f"{required_prefix}s://example.com"  # Starts with "http"
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_starts_with_{required_prefix.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for startswith() patterns - MUST be before default patterns
        startswith_pattern = re.search(r'startswith\((\w+)\.(\w+),\s*"([^"]+)"\)', rego_code)
        if startswith_pattern:
            obj_type = startswith_pattern.group(1)
            field_name = startswith_pattern.group(2)
            prefix = startswith_pattern.group(3)
            
            # Check if there's also a contains() check after startswith (for version format validation)
            # Look for "not contains(...)" after startswith - can be on same line or next line
            contains_after = re.search(r'not\s+contains\([^,)]+,\s*"([^"]+)"\)', rego_code)
            
            if is_spdx and obj_type == "pkg":
                if contains_after:
                    # This is a version format check: starts with "v" but version_num doesn't contain "."
                    required_char = contains_after.group(1)  # e.g., "."
                    # Positive test: starts with prefix but doesn't contain required char
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["packages"][0][field_name] = f"{prefix}123"  # v123 (no dot)
                    tests.append({
                        "name": f"should_deny_when_{field_name.lower()}_starts_with_{prefix}_but_invalid_format",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: starts with prefix and has valid format
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["packages"][0][field_name] = f"{prefix}1.2.3"  # v1.2.3 (has dot)
                    tests.append({
                        "name": f"should_pass_when_{field_name.lower()}_starts_with_{prefix}_and_valid_format",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
                else:
                    # Simple startswith check
                    # Positive test: doesn't start with prefix
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["packages"][0][field_name] = "other-value"
                    tests.append({
                        "name": f"should_deny_when_{field_name.lower()}_not_starts_with_{prefix}",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: starts with prefix
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["packages"][0][field_name] = f"{prefix}value"
                    tests.append({
                        "name": f"should_pass_when_{field_name.lower()}_starts_with_{prefix}",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
        
        # Check for conditional patterns: pkg.field == true AND not pkg.otherField
        conditional_pattern = re.search(r'(pkg|comp)\.(\w+)\s*==\s*true\s*\n\s*not\s+(pkg|comp)\.(\w+)', rego_code)
        if conditional_pattern:
            obj_type1 = conditional_pattern.group(1)
            condition_field = conditional_pattern.group(2)  # e.g., filesAnalyzed
            obj_type2 = conditional_pattern.group(3)
            required_field = conditional_pattern.group(4)  # e.g., packageVerificationCode
            
            if is_spdx and obj_type1 == "pkg" and obj_type2 == "pkg":
                # Positive test: condition is true but required field is missing
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][condition_field] = True
                if required_field in pos_test["statement"]["predicate"]["packages"][0]:
                    del pos_test["statement"]["predicate"]["packages"][0][required_field]
                tests.append({
                    "name": f"should_deny_when_{condition_field.lower()}_true_but_missing_{required_field.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: condition is true and required field is present
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["packages"][0][condition_field] = True
                neg_test["statement"]["predicate"]["packages"][0][required_field] = "abc123"
                tests.append({
                    "name": f"should_pass_when_{condition_field.lower()}_true_and_has_{required_field.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # IMPORTANT: Check Rego code patterns BEFORE natural language patterns
    # This ensures we match based on actual code logic, not just NL description
    
    # Analyze Rego code to understand what it's checking
    # IMPORTANT: Check "not contains" pattern FIRST (before natural language patterns)
    if rego_code:
        # Check for "not contains(pkg.field, \"value\")" pattern FIRST - field doesn't contain required substring
        not_contains_pattern = re.search(r'not\s+contains\((\w+)\.(\w+),\s*"([^"]+)"\)', rego_code)
        if not_contains_pattern:
            obj_type = not_contains_pattern.group(1)
            field_name = not_contains_pattern.group(2)
            required_substring = not_contains_pattern.group(3)
            
            # Check if there's also a != "NOASSERTION" check (for supplier/originator format)
            escaped_field = re.escape(field_name)
            not_noassertion = re.search(rf'{obj_type}\.{escaped_field}\s*!=\s*"NOASSERTION"', rego_code)
            
            if is_spdx and obj_type == "pkg" and not_noassertion:
                # Positive test: field is not "NOASSERTION" but doesn't contain required substring
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = "InvalidFormat"  # No colon
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_invalid_format",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field contains required substring
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["packages"][0][field_name] = "Organization: Test"  # Contains colon
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_valid_format",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # Pattern 3: Check field presence - "Verify all X have a Y"
    if ("all" in nl_lower or "every" in nl_lower) and ("have a " in nl_lower or "have an " in nl_lower or "have " in nl_lower):
        field_name = None
        field_path = None
        
        # Extract field name from natural language
        if "downloadlocation" in nl_lower or "download location" in nl_lower:
            field_name = "downloadLocation"
            field_path = "pkg.downloadLocation"
        elif "name" in nl_lower and ("package" in nl_lower or "component" in nl_lower or "file" in nl_lower):
            field_name = "name"
            field_path = "pkg.name" if "package" in nl_lower else "comp.name" if "component" in nl_lower else "file.fileName"
        elif "version" in nl_lower:
            field_name = "versionInfo" if is_spdx else "version"
            field_path = "pkg.versionInfo" if is_spdx else "comp.version"
        elif "spdxid" in nl_lower:
            field_name = "SPDXID"
            field_path = "pkg.SPDXID" if "package" in nl_lower or "file" in nl_lower else "sbom.SPDXID"
        elif "supplier" in nl_lower and "format" not in nl_lower:  # Only match if it's NOT about format
            field_name = "supplier"
            field_path = "pkg.supplier"
        elif "originator" in nl_lower and "format" not in nl_lower:  # Only match if it's NOT about format
            field_name = "originator"
            field_path = "pkg.originator"
        elif "purl" in nl_lower:
            field_name = "purl"
            field_path = "comp.purl"
        elif "cpe" in nl_lower:
            field_name = "cpe"
            field_path = "comp.cpe"
        elif "bom-ref" in nl_lower or "bomref" in nl_lower:
            field_name = "bom-ref"
            field_path = "comp.bom-ref"
        
        if field_name and field_path:
            if is_spdx and ("package" in nl_lower or "packages" in nl_lower):
                # Positive test: missing field in package
                pos_test = create_base_spdx_attestation()
                if field_name in pos_test["statement"]["predicate"]["packages"][0]:
                    del pos_test["statement"]["predicate"]["packages"][0][field_name]
                tests.append({
                    "name": f"should_deny_when_package_missing_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field present
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_package_has_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            elif is_spdx and ("file" in nl_lower or "files" in nl_lower):
                # Positive test: missing field in file
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["files"] = [{"SPDXID": "SPDXRef-File-test-1"}]
                if field_name == "fileName":
                    pos_test["statement"]["predicate"]["files"][0]["fileName"] = "test.txt"
                tests.append({
                    "name": f"should_deny_when_file_missing_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field present
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["files"] = [{"SPDXID": "SPDXRef-File-test-1", "fileName": "test.txt"}]
                tests.append({
                    "name": f"should_pass_when_file_has_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            elif is_cyclonedx and ("component" in nl_lower or "components" in nl_lower):
                # Positive test: missing field in component
                pos_test = create_base_cyclonedx_attestation()
                if field_name in pos_test["statement"]["predicate"]["components"][0]:
                    if field_name == "bom-ref":
                        # bom-ref is accessed with ["bom-ref"] syntax
                        del pos_test["statement"]["predicate"]["components"][0]["bom-ref"]
                    else:
                        del pos_test["statement"]["predicate"]["components"][0][field_name]
                tests.append({
                    "name": f"should_deny_when_component_missing_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field present
                neg_test = create_base_cyclonedx_attestation()
                tests.append({
                    "name": f"should_pass_when_component_has_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # Pattern 4: Check count/at least
    if ("at least" in nl_lower or "count" in nl_lower) and is_spdx:
        count_match = re.search(r"at least (\d+)", nl_lower)
        if count_match:
            min_count = int(count_match.group(1))
            if "package" in nl_lower:
                # Positive test: fewer packages
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"] = pos_test["statement"]["predicate"]["packages"][:min_count-1]
                tests.append({
                    "name": f"should_deny_when_fewer_than_{min_count}_packages",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: enough packages
                neg_test = create_base_spdx_attestation()
                while len(neg_test["statement"]["predicate"]["packages"]) < min_count:
                    new_pkg = neg_test["statement"]["predicate"]["packages"][0].copy()
                    new_pkg["SPDXID"] = f"SPDXRef-Package-{len(neg_test['statement']['predicate']['packages'])}"
                    new_pkg["name"] = f"package-{len(neg_test['statement']['predicate']['packages'])}"
                    neg_test["statement"]["predicate"]["packages"].append(new_pkg)
                tests.append({
                    "name": f"should_pass_when_at_least_{min_count}_packages",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # Pattern 5: Check format/pattern matching
    if ("format" in nl_lower or "starts with" in nl_lower or "contains" in nl_lower) and is_spdx:
        if "purl" in nl_lower and "pkg:" in nl_lower:
            # Positive test: PURL not starting with pkg:
            pos_test = create_base_spdx_attestation()
            pos_test["statement"]["predicate"]["packages"][0]["externalRefs"][0]["referenceLocator"] = "invalid-purl"
            tests.append({
                "name": "should_deny_when_purl_invalid_format",
                "input": {"attestations": [pos_test]},
                "should_deny": True
            })
            
            # Negative test: valid PURL format
            neg_test = create_base_spdx_attestation()
            tests.append({
                "name": "should_pass_when_purl_valid_format",
                "input": {"attestations": [neg_test]},
                "should_deny": False
            })
            return tests
    
    # Pattern 6: Check uniqueness
    if ("unique" in nl_lower or "duplicate" in nl_lower):
        if is_spdx and "package" in nl_lower:
            # Positive test: duplicate SPDXIDs
            pos_test = create_base_spdx_attestation()
            new_pkg = pos_test["statement"]["predicate"]["packages"][0].copy()
            new_pkg["name"] = "different-name"
            pos_test["statement"]["predicate"]["packages"].append(new_pkg)  # Same SPDXID
            tests.append({
                "name": "should_deny_when_duplicate_spdxids",
                "input": {"attestations": [pos_test]},
                "should_deny": True
            })
            
            # Negative test: unique SPDXIDs
            neg_test = create_base_spdx_attestation()
            new_pkg = neg_test["statement"]["predicate"]["packages"][0].copy()
            new_pkg["SPDXID"] = "SPDXRef-Package-test-2"
            new_pkg["name"] = "different-name"
            neg_test["statement"]["predicate"]["packages"].append(new_pkg)
            tests.append({
                "name": "should_pass_when_unique_spdxids",
                "input": {"attestations": [neg_test]},
                "should_deny": False
            })
            return tests
        
        elif is_cyclonedx and "component" in nl_lower:
            # Positive test: duplicate bom-refs
            pos_test = create_base_cyclonedx_attestation()
            new_comp = pos_test["statement"]["predicate"]["components"][0].copy()
            new_comp["name"] = "different-name"
            pos_test["statement"]["predicate"]["components"].append(new_comp)  # Same bom-ref
            tests.append({
                "name": "should_deny_when_duplicate_bom_refs",
                "input": {"attestations": [pos_test]},
                "should_deny": True
            })
            
            # Negative test: unique bom-refs
            neg_test = create_base_cyclonedx_attestation()
            new_comp = neg_test["statement"]["predicate"]["components"][0].copy()
            new_comp["bom-ref"] = "test-component-ref-2"
            new_comp["name"] = "different-name"
            neg_test["statement"]["predicate"]["components"].append(new_comp)
            tests.append({
                "name": "should_pass_when_unique_bom_refs",
                "input": {"attestations": [neg_test]},
                "should_deny": False
            })
            return tests
    
    # Pattern 7: Check checksums
    if "checksum" in nl_lower:
        if is_spdx:
            if "sha256" in nl_lower or "sha1" in nl_lower:
                algo = "SHA256" if "sha256" in nl_lower else "SHA1"
                # Positive test: missing checksum
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0]["checksums"] = [
                    chk for chk in pos_test["statement"]["predicate"]["packages"][0]["checksums"]
                    if chk["algorithm"] != algo
                ]
                tests.append({
                    "name": f"should_deny_when_missing_{algo.lower()}_checksum",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has checksum
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_has_{algo.lower()}_checksum",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # Pattern 8: Check empty/non-empty
    if ("empty" in nl_lower or "non-empty" in nl_lower):
        if is_spdx and "package" in nl_lower:
            # Positive test: empty field
            pos_test = create_base_spdx_attestation()
            if "name" in nl_lower:
                pos_test["statement"]["predicate"]["packages"][0]["name"] = ""
            elif "version" in nl_lower:
                pos_test["statement"]["predicate"]["packages"][0]["versionInfo"] = ""
            tests.append({
                "name": "should_deny_when_field_empty",
                "input": {"attestations": [pos_test]},
                "should_deny": True
            })
            
            # Negative test: non-empty field
            neg_test = create_base_spdx_attestation()
            tests.append({
                "name": "should_pass_when_field_non_empty",
                "input": {"attestations": [neg_test]},
                "should_deny": False
            })
            return tests
    
    # Analyze Rego code to understand what it's checking
    # IMPORTANT: Check specific value matches FIRST (before empty string or missing field)
    if rego_code:
        # Check for "pkg.field == \"value\"" or "comp.field == \"value\"" pattern - means field equals specific value (should deny)
        # Only match pkg, comp, file, ref, chk, rel - not statement, sbom, att
        equals_value_pattern = re.search(r'(pkg|comp|file|ref|chk|rel)\.(\w+)\s*==\s*"([^"]+)"', rego_code)
        if equals_value_pattern and equals_value_pattern.group(3) != "":  # Not empty string
            obj_type = equals_value_pattern.group(1)
            field_name = equals_value_pattern.group(2)
            forbidden_value = equals_value_pattern.group(3)
            
            if is_spdx and obj_type == "pkg":
                # Positive test: field equals forbidden value
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = forbidden_value
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_equals_{forbidden_value.lower().replace('(', '').replace(')', '').replace(' ', '_').replace('-', '_')}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field has different value
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_not_equals_{forbidden_value.lower().replace('(', '').replace(')', '').replace(' ', '_').replace('-', '_')}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "not startswith()" patterns FIRST - means field does NOT start with prefix
        not_startswith_pattern = re.search(r'not\s+startswith\((\w+)\.(\w+),\s*"([^"]+)"\)', rego_code)
        if not_startswith_pattern:
            obj_type = not_startswith_pattern.group(1)
            field_name = not_startswith_pattern.group(2)
            required_prefix = not_startswith_pattern.group(3)
            
            if is_spdx and obj_type == "sbom":
                # Positive test: does NOT start with required prefix
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"][field_name] = "invalid-value"  # Doesn't start with "http"
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_not_starts_with_{required_prefix.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: starts with required prefix
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"][field_name] = f"{required_prefix}s://example.com"  # Starts with "http"
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_starts_with_{required_prefix.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for startswith() patterns - MUST be before default patterns
        startswith_pattern = re.search(r'startswith\((\w+)\.(\w+),\s*"([^"]+)"\)', rego_code)
        if startswith_pattern:
            obj_type = startswith_pattern.group(1)
            field_name = startswith_pattern.group(2)
            prefix = startswith_pattern.group(3)
            
            # Check if there's also a contains() check after startswith (for version format validation)
            # Look for "not contains(...)" after startswith - can be on same line or next line
            contains_after = re.search(r'not\s+contains\([^,)]+,\s*"([^"]+)"\)', rego_code)
            
            if is_spdx and obj_type == "pkg":
                if contains_after:
                    # This is a version format check: starts with "v" but version_num doesn't contain "."
                    required_char = contains_after.group(1)  # e.g., "."
                    # Positive test: starts with prefix but doesn't contain required char
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["packages"][0][field_name] = f"{prefix}123"  # v123 (no dot)
                    tests.append({
                        "name": f"should_deny_when_{field_name.lower()}_starts_with_{prefix}_but_invalid_format",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: starts with prefix and has valid format
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["packages"][0][field_name] = f"{prefix}1.2.3"  # v1.2.3 (has dot)
                    tests.append({
                        "name": f"should_pass_when_{field_name.lower()}_starts_with_{prefix}_and_valid_format",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
                else:
                    # Simple startswith check
                    # Positive test: doesn't start with prefix
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["packages"][0][field_name] = "other-value"
                    tests.append({
                        "name": f"should_deny_when_{field_name.lower()}_not_starts_with_{prefix}",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: starts with prefix
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["packages"][0][field_name] = f"{prefix}value"
                    tests.append({
                        "name": f"should_pass_when_{field_name.lower()}_starts_with_{prefix}",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
        
        # Check for conditional patterns: pkg.field == true AND not pkg.otherField
        conditional_pattern = re.search(r'(pkg|comp)\.(\w+)\s*==\s*true\s*\n\s*not\s+(pkg|comp)\.(\w+)', rego_code)
        if conditional_pattern:
            obj_type1 = conditional_pattern.group(1)
            condition_field = conditional_pattern.group(2)  # e.g., filesAnalyzed
            obj_type2 = conditional_pattern.group(3)
            required_field = conditional_pattern.group(4)  # e.g., packageVerificationCode
            
            if is_spdx and obj_type1 == "pkg" and obj_type2 == "pkg":
                # Positive test: condition is true but required field is missing
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][condition_field] = True
                if required_field in pos_test["statement"]["predicate"]["packages"][0]:
                    del pos_test["statement"]["predicate"]["packages"][0][required_field]
                tests.append({
                    "name": f"should_deny_when_{condition_field.lower()}_true_but_missing_{required_field.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: condition is true and required field is present
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["packages"][0][condition_field] = True
                neg_test["statement"]["predicate"]["packages"][0][required_field] = "abc123"
                tests.append({
                    "name": f"should_pass_when_{condition_field.lower()}_true_and_has_{required_field.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "== \"\"" pattern FIRST - means field is empty string (must be before "not field")
        empty_string_pattern = re.search(r'(\w+)\.(\w+)\s*==\s*""', rego_code)
        if empty_string_pattern:
            obj_type = empty_string_pattern.group(1)
            field_name = empty_string_pattern.group(2)
            
            if is_spdx and obj_type == "file":
                # Positive test: empty field in file
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    field_name: ""  # Empty string
                }]
                tests.append({
                    "name": f"should_deny_when_file_{field_name.lower()}_empty",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: non-empty field
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    field_name: "test.txt"  # Non-empty
                }]
                tests.append({
                    "name": f"should_pass_when_file_{field_name.lower()}_non_empty",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "== \"\"" pattern FIRST - means field is empty string (must be before "not field")
        empty_string_pattern = re.search(r'(\w+)\.(\w+)\s*==\s*""', rego_code)
        if empty_string_pattern:
            obj_type = empty_string_pattern.group(1)
            field_name = empty_string_pattern.group(2)
            
            if is_spdx and obj_type == "file":
                # Positive test: empty field in file
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    field_name: ""  # Empty string
                }]
                tests.append({
                    "name": f"should_deny_when_file_{field_name.lower()}_empty",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: non-empty field
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    field_name: "test.txt"  # Non-empty
                }]
                tests.append({
                    "name": f"should_pass_when_file_{field_name.lower()}_non_empty",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for uniqueness patterns FIRST (before not_field_pattern)
        # Pattern: count(set) != count(list) means duplicates exist
        uniqueness_pattern = re.search(r'count\(([^)]+)\)\s*!=\s*count\(([^)]+)\)', rego_code)
        if uniqueness_pattern:
            set_var = uniqueness_pattern.group(1).strip()
            list_var = uniqueness_pattern.group(2).strip()
            
            # Check for file SPDXID uniqueness: file_ids := {file.SPDXID | ...}; count(file_ids) != count(sbom.files)
            # Pattern: file_ids or similar variable name, and list_var contains "files"
            if ("file" in set_var.lower() or "id" in set_var.lower()) and "files" in list_var.lower() and is_spdx:
                # Check if the Rego code has file.SPDXID in the set comprehension (case-insensitive)
                if "file.spdxid" in rego_code.lower():
                    # Positive test: duplicate file SPDXIDs
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["files"] = [
                        {"SPDXID": "SPDXRef-File-test-1", "fileName": "file1.txt"},
                        {"SPDXID": "SPDXRef-File-test-1", "fileName": "file2.txt"}  # Duplicate SPDXID
                    ]
                    tests.append({
                        "name": "should_deny_when_duplicate_file_spdxids",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: unique file SPDXIDs
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["files"] = [
                        {"SPDXID": "SPDXRef-File-test-1", "fileName": "file1.txt"},
                        {"SPDXID": "SPDXRef-File-test-2", "fileName": "file2.txt"}  # Unique SPDXIDs
                    ]
                    tests.append({
                        "name": "should_pass_when_unique_file_spdxids",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
            
            # Check for checksum algorithm uniqueness: chk_algorithms := {chk.algorithm | ...}; count(chk_algorithms) != count(file.checksums)
            # Pattern: chk_algorithms or similar variable name, and list_var contains "checksums"
            if ("chk" in set_var.lower() or "algorithm" in set_var.lower()) and "checksums" in list_var.lower() and is_spdx:
                # Check if the Rego code has chk.algorithm in the set comprehension
                if "chk.algorithm" in rego_code.lower() or "chk.algorithm" in rego_code:
                    # Positive test: duplicate checksum algorithms
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["files"] = [{
                        "SPDXID": "SPDXRef-File-test-1",
                        "fileName": "test.txt",
                        "checksums": [
                            {"algorithm": "SHA256", "checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"algorithm": "SHA256", "checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}  # Duplicate algorithm
                        ]
                    }]
                    tests.append({
                        "name": "should_deny_when_duplicate_checksum_algorithms",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: unique checksum algorithms
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["files"] = [{
                        "SPDXID": "SPDXRef-File-test-1",
                        "fileName": "test.txt",
                        "checksums": [
                            {"algorithm": "SHA256", "checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                            {"algorithm": "SHA1", "checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}  # Unique algorithms
                        ]
                    }]
                    tests.append({
                        "name": "should_pass_when_unique_checksum_algorithms",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
        
        # Check for "not contains(pkg.field, \"value\")" pattern FIRST - field doesn't contain required substring (before not_field_pattern)
        not_contains_pattern = re.search(r'not\s+contains\((\w+)\.(\w+),\s*"([^"]+)"\)', rego_code)
        if not_contains_pattern:
            obj_type = not_contains_pattern.group(1)
            field_name = not_contains_pattern.group(2)
            required_substring = not_contains_pattern.group(3)
            
            # Check if there's also a != "NOASSERTION" check (for supplier/originator format)
            # Escape the field name for regex
            escaped_field = re.escape(field_name)
            not_noassertion = re.search(rf'{obj_type}\.{escaped_field}\s*!=\s*"NOASSERTION"', rego_code)
            
            if is_spdx and obj_type == "pkg" and not_noassertion:
                # Positive test: field is not "NOASSERTION" but doesn't contain required substring
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = "InvalidFormat"  # No colon
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_invalid_format",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field contains required substring
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["packages"][0][field_name] = f"Organization: Test"  # Contains colon
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_valid_format",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "not pkg." or "not comp." patterns (but NOT "not contains(...)")
        # Make sure we don't match "not contains(...)" - that's handled above
        # First check if there's a "not contains" pattern - if so, skip not_field_pattern
        has_not_contains = re.search(r'not\s+contains\(', rego_code)
        not_field_pattern = None
        if not has_not_contains:
            # Only check for not_field_pattern if there's no not_contains pattern
            not_field_pattern = re.search(r'not\s+(pkg|comp|file|sbom)\.(\w+)', rego_code)
        
        if not_field_pattern:
            obj_type = not_field_pattern.group(1)  # pkg, comp, file, sbom
            field_name = not_field_pattern.group(2)  # field name
            
            if is_spdx and obj_type == "pkg":
                # Positive test: missing field
                pos_test = create_base_spdx_attestation()
                if field_name in pos_test["statement"]["predicate"]["packages"][0]:
                    del pos_test["statement"]["predicate"]["packages"][0][field_name]
                tests.append({
                    "name": f"should_deny_when_package_missing_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field present
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_package_has_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            elif is_spdx and obj_type == "file":
                # Positive test: missing field in file
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["files"] = [{"SPDXID": "SPDXRef-File-test-1"}]
                # Don't add the field - it's missing
                tests.append({
                    "name": f"should_deny_when_file_missing_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field present
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["files"] = [{"SPDXID": "SPDXRef-File-test-1", field_name: "test.txt"}]
                tests.append({
                    "name": f"should_pass_when_file_has_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            elif is_cyclonedx and obj_type == "comp":
                # Positive test: missing field
                pos_test = create_base_cyclonedx_attestation()
                if field_name == "bom-ref":
                    if "bom-ref" in pos_test["statement"]["predicate"]["components"][0]:
                        del pos_test["statement"]["predicate"]["components"][0]["bom-ref"]
                elif field_name in pos_test["statement"]["predicate"]["components"][0]:
                    del pos_test["statement"]["predicate"]["components"][0][field_name]
                tests.append({
                    "name": f"should_deny_when_component_missing_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field present
                neg_test = create_base_cyclonedx_attestation()
                tests.append({
                    "name": f"should_pass_when_component_has_{field_name.lower().replace('-', '_')}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            # Check for relationships (SPDX) - "not rel.field"
            elif is_spdx and obj_type == "rel" and "relationship" in nl_lower:
                # Positive test: missing field in relationship
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["relationships"] = [{
                    "relationshipType": "DEPENDS_ON"
                    # Missing spdxElementId
                }]
                tests.append({
                    "name": f"should_deny_when_relationship_missing_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field present
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["relationships"] = [{
                    "spdxElementId": "SPDXRef-Package-test-1",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": "SPDXRef-Package-test-2"
                }]
                tests.append({
                    "name": f"should_pass_when_relationship_has_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for variable assignment pattern: var := count([...]); var == 0
        # Pattern: analyzed_count := count([pkg | ...; pkg.field == true]); analyzed_count == 0
        var_assign_pattern = re.search(r'(\w+)\s*:=\s*count\(\[([^\]]+)\]\)', rego_code)
        if var_assign_pattern:
            var_name = var_assign_pattern.group(1)
            collection_expr = var_assign_pattern.group(2)
            
            # Check if var_name == 0
            var_eq_zero = re.search(f'{var_name}\\s*==\\s*0', rego_code)
            if var_eq_zero:
                # Check for pkg.field == true in collection_expr
                field_eq_true_match = re.search(r'pkg\.(\w+)\s*==\s*true', collection_expr)
                if field_eq_true_match and is_spdx:
                    field_name = field_eq_true_match.group(1)
                    # Positive test: no packages with field == true
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["packages"][0][field_name] = False
                    tests.append({
                        "name": f"should_deny_when_no_packages_with_{field_name.lower()}_true",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: has packages with field == true
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["packages"][0][field_name] = True
                    tests.append({
                        "name": f"should_pass_when_has_packages_with_{field_name.lower()}_true",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
        
        # Check for "count(...) == 0" pattern - means collection is empty
        count_zero_pattern = re.search(r'count\(([^)]+)\)\s*==\s*0', rego_code)
        if count_zero_pattern:
            collection = count_zero_pattern.group(1)
            
            # Check for count([pkg | ...; pkg.field == true]) == 0 FIRST - means no packages match condition
            # Pattern: count([pkg | some pkg in sbom.packages; pkg.field == true]) == 0
            # This must be checked BEFORE the simple pkg.field pattern
            field_eq_true_match = re.search(r'pkg\.(\w+)\s*==\s*true', rego_code)
            if field_eq_true_match and "[" in collection and "pkg" in collection.lower():
                field_name = field_eq_true_match.group(1)
                # Positive test: no packages with field == true
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = False
                tests.append({
                    "name": f"should_deny_when_no_packages_with_{field_name.lower()}_true",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has packages with field == true
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["packages"][0][field_name] = True
                tests.append({
                    "name": f"should_pass_when_has_packages_with_{field_name.lower()}_true",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            # Check for count(pkg.checksums) == 0 or count(pkg.field) == 0
            pkg_field_pattern = re.search(r'pkg\.(\w+)', collection)
            if pkg_field_pattern and is_spdx and "[" not in collection:
                field_name = pkg_field_pattern.group(1)
                # Positive test: empty field (empty array)
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = []
                tests.append({
                    "name": f"should_deny_when_package_has_no_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field has items
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_package_has_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            # Check for count(comp.field) == 0
            comp_field_pattern = re.search(r'comp\.(\w+)', collection)
            if comp_field_pattern and is_cyclonedx:
                field_name = comp_field_pattern.group(1)
                # Positive test: empty field
                pos_test = create_base_cyclonedx_attestation()
                pos_test["statement"]["predicate"]["components"][0][field_name] = []
                tests.append({
                    "name": f"should_deny_when_component_has_no_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: field has items
                neg_test = create_base_cyclonedx_attestation()
                tests.append({
                    "name": f"should_pass_when_component_has_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            
            # Check for count(sbom.creationInfo.creators) == 0
            if "creationinfo" in collection.lower() and "creators" in collection.lower() and is_spdx:
                # Positive test: no creators
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["creationInfo"]["creators"] = []
                tests.append({
                    "name": "should_deny_when_no_creators",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has creators
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": "should_pass_when_has_creators",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            if "packages" in collection and is_spdx:
                # Positive test: empty packages
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"] = []
                tests.append({
                    "name": "should_deny_when_no_packages",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has packages
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": "should_pass_when_has_packages",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            elif "components" in collection and is_cyclonedx:
                # Positive test: empty components
                pos_test = create_base_cyclonedx_attestation()
                pos_test["statement"]["predicate"]["components"] = []
                tests.append({
                    "name": "should_deny_when_no_components",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has components
                neg_test = create_base_cyclonedx_attestation()
                tests.append({
                    "name": "should_pass_when_has_components",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "count(...) < N" pattern - means fewer than N
        count_lt_pattern = re.search(r'count\(([^)]+)\)\s*<\s*(\d+)', rego_code)
        if count_lt_pattern:
            collection = count_lt_pattern.group(1)
            min_count = int(count_lt_pattern.group(2))
            if "packages" in collection and is_spdx:
                # Positive test: fewer packages
                pos_test = create_base_spdx_attestation()
                # Keep only min_count - 1 packages
                pos_test["statement"]["predicate"]["packages"] = pos_test["statement"]["predicate"]["packages"][:max(0, min_count-1)]
                tests.append({
                    "name": f"should_deny_when_fewer_than_{min_count}_packages",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: enough packages
                neg_test = create_base_spdx_attestation()
                while len(neg_test["statement"]["predicate"]["packages"]) < min_count:
                    new_pkg = neg_test["statement"]["predicate"]["packages"][0].copy()
                    new_pkg["SPDXID"] = f"SPDXRef-Package-{len(neg_test['statement']['predicate']['packages'])}"
                    new_pkg["name"] = f"package-{len(neg_test['statement']['predicate']['packages'])}"
                    neg_test["statement"]["predicate"]["packages"].append(new_pkg)
                tests.append({
                    "name": f"should_pass_when_at_least_{min_count}_packages",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for nested field empty string: pkg.field.field == ""
        nested_empty_pattern = re.search(r'(\w+)\.(\w+)\.(\w+)\s*==\s*""', rego_code)
        if nested_empty_pattern:
            obj_type = nested_empty_pattern.group(1)
            field1 = nested_empty_pattern.group(2)
            field2 = nested_empty_pattern.group(3)
            
            if is_spdx and obj_type == "pkg":
                # Positive test: nested field is empty
                pos_test = create_base_spdx_attestation()
                if field1 not in pos_test["statement"]["predicate"]["packages"][0]:
                    pos_test["statement"]["predicate"]["packages"][0][field1] = {}
                pos_test["statement"]["predicate"]["packages"][0][field1][field2] = ""
                tests.append({
                    "name": f"should_deny_when_{field1.lower()}_{field2.lower()}_empty",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: nested field is non-empty
                neg_test = create_base_spdx_attestation()
                if field1 not in neg_test["statement"]["predicate"]["packages"][0]:
                    neg_test["statement"]["predicate"]["packages"][0][field1] = {}
                neg_test["statement"]["predicate"]["packages"][0][field1][field2] = "non-empty-value"
                tests.append({
                    "name": f"should_pass_when_{field1.lower()}_{field2.lower()}_non_empty",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "== \"\"" pattern - means field is empty string (for packages)
        empty_string_pattern = re.search(r'(\w+)\.(\w+)\s*==\s*""', rego_code)
        if empty_string_pattern:
            obj_type = empty_string_pattern.group(1)
            field_name = empty_string_pattern.group(2)
            
            if is_spdx and obj_type == "pkg":
                # Positive test: empty field
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = ""
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_empty",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: non-empty field
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_non_empty",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "not (x in [...])" pattern - means value is NOT in allowed list
        not_in_list_pattern = re.search(r'not\s+\((\w+)\.(\w+)\s+in\s+\[([^\]]+)\]\)', rego_code)
        if not_in_list_pattern:
            obj_type = not_in_list_pattern.group(1)  # comp, pkg, etc.
            field_name = not_in_list_pattern.group(2)  # type, etc.
            allowed_values_str = not_in_list_pattern.group(3)
            # Extract allowed values from the list
            allowed_values = [v.strip().strip('"') for v in allowed_values_str.split(',')]
            
            if is_cyclonedx and obj_type == "comp":
                # Positive test: invalid value (not in allowed list)
                pos_test = create_base_cyclonedx_attestation()
                # Use an invalid value
                pos_test["statement"]["predicate"]["components"][0][field_name] = "invalid-type"
                tests.append({
                    "name": f"should_deny_when_component_has_invalid_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: valid value (in allowed list)
                neg_test = create_base_cyclonedx_attestation()
                # Use first valid value from allowed list
                neg_test["statement"]["predicate"]["components"][0][field_name] = allowed_values[0]
                tests.append({
                    "name": f"should_pass_when_component_has_valid_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            elif is_spdx and obj_type == "pkg":
                # Positive test: invalid value
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0][field_name] = "invalid-value"
                tests.append({
                    "name": f"should_deny_when_package_has_invalid_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: valid value
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"]["packages"][0][field_name] = allowed_values[0]
                tests.append({
                    "name": f"should_pass_when_package_has_valid_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
        
        # Check for "count([...]) == 0" with complex conditions (e.g., count([x | condition]) == 0)
        # This means no element matches the condition
        count_complex_zero_pattern = re.search(r'count\(\[([^\|]+)\s*\|\s*([^\]]+)\]\s*\)\s*==\s*0', rego_code)
        if count_complex_zero_pattern:
            var = count_complex_zero_pattern.group(1).strip()
            condition = count_complex_zero_pattern.group(2).strip()
            
            # Check if it's checking for PACKAGE_MANAGER external refs
            if "packagemanager" in condition.lower().replace("_", "").replace("-", "") and "externalref" in condition.lower() and is_spdx:
                # Positive test: no PACKAGE_MANAGER external ref
                pos_test = create_base_spdx_attestation()
                # Remove PACKAGE_MANAGER external refs (keep others or remove all)
                pos_test["statement"]["predicate"]["packages"][0]["externalRefs"] = [
                    ref for ref in pos_test["statement"]["predicate"]["packages"][0].get("externalRefs", [])
                    if ref.get("referenceCategory") != "PACKAGE_MANAGER"
                ]
                # If no refs left, set to empty array
                if not pos_test["statement"]["predicate"]["packages"][0]["externalRefs"]:
                    pos_test["statement"]["predicate"]["packages"][0]["externalRefs"] = []
                tests.append({
                    "name": "should_deny_when_no_package_manager_external_ref",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has PACKAGE_MANAGER external ref
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": "should_pass_when_has_package_manager_external_ref",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            # Check if it's checking for PURL external refs
            if "purl" in condition.lower() and "externalref" in condition.lower() and is_spdx:
                # Positive test: no PURL external ref
                pos_test = create_base_spdx_attestation()
                # Remove PURL external refs
                pos_test["statement"]["predicate"]["packages"][0]["externalRefs"] = [
                    ref for ref in pos_test["statement"]["predicate"]["packages"][0].get("externalRefs", [])
                    if ref.get("referenceType") != "purl"
                ]
                # If no refs left, set to empty array
                if not pos_test["statement"]["predicate"]["packages"][0]["externalRefs"]:
                    pos_test["statement"]["predicate"]["packages"][0]["externalRefs"] = []
                tests.append({
                    "name": "should_deny_when_no_purl_external_ref",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has PURL external ref
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": "should_pass_when_has_purl_external_ref",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
            
            # Check for count([...]) == 0 with contains() - means no element contains the string
            if "contains(" in condition.lower():
                # Extract the contains pattern
                contains_match = re.search(r'contains\([^,]+,\s*"([^"]+)"\)', condition)
                if contains_match:
                    search_string = contains_match.group(1)
                    # Check what we're searching in
                    if "purl" in var.lower() and "rpm" in search_string.lower():
                        # Positive test: no PURLs containing "rpm"
                        pos_test = create_base_spdx_attestation()
                        # Change PURL to not contain "rpm"
                        pos_test["statement"]["predicate"]["packages"][0]["externalRefs"] = [{
                            "referenceCategory": "PACKAGE_MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/test-package@1.0.0"  # npm, not rpm
                        }]
                        tests.append({
                            "name": f"should_deny_when_no_purl_contains_{search_string.lower()}",
                            "input": {"attestations": [pos_test]},
                            "should_deny": True
                        })
                        
                        # Negative test: has PURL containing "rpm"
                        neg_test = create_base_spdx_attestation()
                        tests.append({
                            "name": f"should_pass_when_has_purl_contains_{search_string.lower()}",
                            "input": {"attestations": [neg_test]},
                            "should_deny": False
                        })
                        return tests
            
            # Check if it's checking for checksums
            if "checksum" in condition.lower() and ("sha256" in condition.lower() or "sha1" in condition.lower()):
                algo = "SHA256" if "sha256" in condition.lower() else "SHA1"
                if is_spdx and "pkg" in var.lower():
                    # Positive test: missing checksum
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["packages"][0]["checksums"] = [
                        chk for chk in pos_test["statement"]["predicate"]["packages"][0].get("checksums", [])
                        if chk.get("algorithm") != algo
                    ]
                    tests.append({
                        "name": f"should_deny_when_missing_{algo.lower()}_checksum",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: has checksum
                    neg_test = create_base_spdx_attestation()
                    tests.append({
                        "name": f"should_pass_when_has_{algo.lower()}_checksum",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
                elif is_spdx and "file" in var.lower():
                    # Positive test: missing checksum in file
                    pos_test = create_base_spdx_attestation()
                    pos_test["statement"]["predicate"]["files"] = [{"SPDXID": "SPDXRef-File-test-1", "fileName": "test.txt"}]
                    tests.append({
                        "name": f"should_deny_when_file_missing_{algo.lower()}_checksum",
                        "input": {"attestations": [pos_test]},
                        "should_deny": True
                    })
                    
                    # Negative test: has checksum
                    neg_test = create_base_spdx_attestation()
                    neg_test["statement"]["predicate"]["files"] = [{
                        "SPDXID": "SPDXRef-File-test-1",
                        "fileName": "test.txt",
                        "checksums": [{"algorithm": algo, "checksumValue": "a" * (64 if algo == "SHA256" else 40)}]
                    }]
                    tests.append({
                        "name": f"should_pass_when_file_has_{algo.lower()}_checksum",
                        "input": {"attestations": [neg_test]},
                        "should_deny": False
                    })
                    return tests
        
        # Check for "!= \"value\"" pattern - means field doesn't equal value
        not_equal_pattern = re.search(r'(\w+)\.(\w+)\s*!=\s*"([^"]+)"', rego_code)
        if not_equal_pattern:
            obj_type = not_equal_pattern.group(1)
            field_name = not_equal_pattern.group(2)
            expected_value = not_equal_pattern.group(3)
            
            if is_spdx and obj_type == "sbom":
                # Positive test: wrong value
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"][field_name] = "wrong-value"
                tests.append({
                    "name": f"should_deny_when_{field_name.lower()}_wrong",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: correct value
                neg_test = create_base_spdx_attestation()
                neg_test["statement"]["predicate"][field_name] = expected_value
                tests.append({
                    "name": f"should_pass_when_{field_name.lower()}_correct",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # Check for uniqueness patterns (count(set) != count(list))
    # Pattern: count(set) != count(list) means duplicates exist
    uniqueness_pattern = re.search(r'count\(([^)]+)\)\s*!=\s*count\(([^)]+)\)', rego_code)
    if uniqueness_pattern:
        set_var = uniqueness_pattern.group(1).strip()
        list_var = uniqueness_pattern.group(2).strip()
        
        # Check for file SPDXID uniqueness: file_ids := {file.SPDXID | ...}; count(file_ids) != count(sbom.files)
        if "file" in set_var.lower() and "spdxid" in set_var.lower() and "files" in list_var.lower() and is_spdx:
            # Positive test: duplicate file SPDXIDs
            pos_test = create_base_spdx_attestation()
            pos_test["statement"]["predicate"]["files"] = [
                {"SPDXID": "SPDXRef-File-test-1", "fileName": "file1.txt"},
                {"SPDXID": "SPDXRef-File-test-1", "fileName": "file2.txt"}  # Duplicate SPDXID
            ]
            tests.append({
                "name": "should_deny_when_duplicate_file_spdxids",
                "input": {"attestations": [pos_test]},
                "should_deny": True
            })
            
            # Negative test: unique file SPDXIDs
            neg_test = create_base_spdx_attestation()
            neg_test["statement"]["predicate"]["files"] = [
                {"SPDXID": "SPDXRef-File-test-1", "fileName": "file1.txt"},
                {"SPDXID": "SPDXRef-File-test-2", "fileName": "file2.txt"}  # Unique SPDXIDs
            ]
            tests.append({
                "name": "should_pass_when_unique_file_spdxids",
                "input": {"attestations": [neg_test]},
                "should_deny": False
            })
            return tests
        
        # Check for checksum algorithm uniqueness: chk_algorithms := {chk.algorithm | ...}; count(chk_algorithms) != count(file.checksums)
        if "chk" in set_var.lower() and "algorithm" in set_var.lower() and "checksums" in list_var.lower() and is_spdx:
            # Positive test: duplicate checksum algorithms
            pos_test = create_base_spdx_attestation()
            pos_test["statement"]["predicate"]["files"] = [{
                "SPDXID": "SPDXRef-File-test-1",
                "fileName": "test.txt",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    {"algorithm": "SHA256", "checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}  # Duplicate algorithm
                ]
            }]
            tests.append({
                "name": "should_deny_when_duplicate_checksum_algorithms",
                "input": {"attestations": [pos_test]},
                "should_deny": True
            })
            
            # Negative test: unique checksum algorithms
            neg_test = create_base_spdx_attestation()
            neg_test["statement"]["predicate"]["files"] = [{
                "SPDXID": "SPDXRef-File-test-1",
                "fileName": "test.txt",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                    {"algorithm": "SHA1", "checksumValue": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}  # Unique algorithms
                ]
            }]
            tests.append({
                "name": "should_pass_when_unique_checksum_algorithms",
                "input": {"attestations": [neg_test]},
                "should_deny": False
            })
            return tests
    
    # Check for uniqueness patterns (count(set) != count(list)) - legacy check
    if rego_code and "unique" in nl_lower:
        # Pattern: count(set) != count(list) means duplicates exist
        uniqueness_pattern = re.search(r'count\(([^)]+)\)\s*!=\s*count\(([^)]+)\)', rego_code)
        if uniqueness_pattern:
            set_var = uniqueness_pattern.group(1).strip()
            list_var = uniqueness_pattern.group(2).strip()
            
            if "name" in nl_lower and is_spdx:
                # Positive test: duplicate names (two SBOMs with same name)
                pos_test1 = create_base_spdx_attestation()
                pos_test2 = create_base_spdx_attestation()
                # Same name for both
                pos_test2["statement"]["predicate"]["name"] = pos_test1["statement"]["predicate"]["name"]
                tests.append({
                    "name": "should_deny_when_duplicate_names",
                    "input": {"attestations": [pos_test1, pos_test2]},
                    "should_deny": True
                })
                
                # Negative test: unique names
                neg_test1 = create_base_spdx_attestation()
                neg_test2 = create_base_spdx_attestation()
                neg_test2["statement"]["predicate"]["name"] = "different-name@sha256:def456"
                tests.append({
                    "name": "should_pass_when_unique_names",
                    "input": {"attestations": [neg_test1, neg_test2]},
                    "should_deny": False
                })
                return tests
            
            elif "spdxid" in nl_lower and is_spdx:
                # Positive test: duplicate SPDXIDs
                pos_test = create_base_spdx_attestation()
                new_pkg = pos_test["statement"]["predicate"]["packages"][0].copy()
                new_pkg["name"] = "different-name"
                # Same SPDXID
                pos_test["statement"]["predicate"]["packages"].append(new_pkg)
                tests.append({
                    "name": "should_deny_when_duplicate_spdxids",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: unique SPDXIDs
                neg_test = create_base_spdx_attestation()
                new_pkg = neg_test["statement"]["predicate"]["packages"][0].copy()
                new_pkg["SPDXID"] = "SPDXRef-Package-test-2"
                new_pkg["name"] = "different-name"
                neg_test["statement"]["predicate"]["packages"].append(new_pkg)
                tests.append({
                    "name": "should_pass_when_unique_spdxids",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # Check for "not ref.referenceLocator" pattern - missing field in nested object
    if rego_code:
        not_nested_field_pattern = re.search(r'not\s+(\w+)\.(\w+)', rego_code)
        if not_nested_field_pattern and not not_field_pattern:  # Don't duplicate with earlier pattern
            obj_type = not_nested_field_pattern.group(1)  # ref, chk, etc.
            field_name = not_nested_field_pattern.group(2)  # referenceLocator, etc.
            
            if is_spdx and obj_type == "ref" and "externalref" in rego_code.lower():
                # Positive test: missing referenceLocator in externalRef
                pos_test = create_base_spdx_attestation()
                pos_test["statement"]["predicate"]["packages"][0]["externalRefs"] = [{
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": "purl"
                    # Missing referenceLocator
                }]
                tests.append({
                    "name": f"should_deny_when_external_ref_missing_{field_name.lower()}",
                    "input": {"attestations": [pos_test]},
                    "should_deny": True
                })
                
                # Negative test: has referenceLocator
                neg_test = create_base_spdx_attestation()
                tests.append({
                    "name": f"should_pass_when_external_ref_has_{field_name.lower()}",
                    "input": {"attestations": [neg_test]},
                    "should_deny": False
                })
                return tests
    
    # Default: Create basic positive/negative tests
    if is_spdx:
        # Positive test: missing required field or invalid value
        pos_test = create_base_spdx_attestation()
        if "package" in nl_lower:
            # Remove a common field
            if "name" in pos_test["statement"]["predicate"]["packages"][0]:
                del pos_test["statement"]["predicate"]["packages"][0]["name"]
        tests.append({
            "name": "should_deny_when_condition_violated",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        # Negative test: valid structure
        neg_test = create_base_spdx_attestation()
        tests.append({
            "name": "should_pass_when_condition_met",
            "input": {"attestations": [neg_test]},
            "should_deny": False
        })
    elif is_cyclonedx:
        # Positive test: missing required field or invalid value
        pos_test = create_base_cyclonedx_attestation()
        if "component" in nl_lower:
            # Remove a common field
            if "name" in pos_test["statement"]["predicate"]["components"][0]:
                del pos_test["statement"]["predicate"]["components"][0]["name"]
        tests.append({
            "name": "should_deny_when_condition_violated",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        # Negative test: valid structure
        neg_test = create_base_cyclonedx_attestation()
        tests.append({
            "name": "should_pass_when_condition_met",
            "input": {"attestations": [neg_test]},
            "should_deny": False
        })
    else:
        # Fallback: use SPDX
        pos_test = create_base_spdx_attestation()
        pos_test["statement"]["predicate"]["packages"] = []
        tests.append({
            "name": "should_deny_when_condition_violated",
            "input": {"attestations": [pos_test]},
            "should_deny": True
        })
        
        neg_test = create_base_spdx_attestation()
        tests.append({
            "name": "should_pass_when_condition_met",
            "input": {"attestations": [neg_test]},
            "should_deny": False
        })
    
    return tests

def main():
    """Generate validation tests for all SBOM test cases.
    
    Uses comprehensive_test_cases.json as source of truth for rego_code,
    then generates test data that properly validates the rules.
    """
    project_root = Path(__file__).parent.parent.parent
    
    # Load comprehensive test cases (source of truth for rego_code)
    comprehensive_file = project_root / "sbom_data" / "comprehensive_test_cases.json"
    
    if not comprehensive_file.exists():
        print(f"Error: {comprehensive_file} does not exist")
        return
    
    with open(comprehensive_file) as f:
        comprehensive = json.load(f)
    
    # Create output structure
    test_definitions = {
        "metadata": {
            "description": "SBOM validation test cases generated from comprehensive_test_cases.json",
            "total_test_cases": 0
        },
        "test_cases": {}
    }
    
    test_cases = comprehensive.get("test_cases", {})
    print(f"Generating validation tests for {len(test_cases)} SBOM test cases...")
    
    generated = 0
    skipped = 0
    
    for case_id, test_case in test_cases.items():
        try:
            tests = generate_sbom_validation_tests(test_case, case_id)
            if tests:
                test_definitions["test_cases"][case_id] = {
                    "natural_language": test_case["natural_language"],
                    "rego_code": test_case.get("rego_code", ""),
                    "keys_used": test_case.get("keys_used", []),
                    "type": test_case.get("type", "compound"),
                    "tests": tests
                }
                generated += 1
                if generated % 50 == 0:
                    print(f"  Generated tests for {generated} cases...")
            else:
                skipped += 1
        except Exception as e:
            print(f"  WARNING: Failed to generate tests for {case_id}: {e}")
            skipped += 1
    
    test_definitions["metadata"]["total_test_cases"] = generated
    
    # Save output
    output_file = project_root / "sbom_data" / "test_case_definitions.json"
    with open(output_file, 'w') as f:
        json.dump(test_definitions, f, indent=2)
    
    print(f"\n✅ Generated validation tests for {generated} test cases")
    if skipped > 0:
        print(f"⚠️  Skipped {skipped} test cases")
    print(f"📁 Output: {output_file}")

if __name__ == "__main__":
    main()
