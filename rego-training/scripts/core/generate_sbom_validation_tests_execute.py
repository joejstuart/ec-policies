#!/usr/bin/env python3
"""
Generate SBOM validation test data by executing Rego rules.

This approach:
1. Generates candidate test data based on natural language + keys_used
2. Executes the Rego rule with that test data using OPA
3. If rule denies → positive test (should_deny: true)
4. If rule doesn't deny → negative test (should_deny: false)
5. Verifies we have both positive and negative tests

This is more accurate than pattern matching because we actually test the rule.
"""

import copy
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Get the project root (parent of scripts/core)
PROJECT_ROOT = Path(__file__).parent.parent.parent

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

def execute_rego_rule(rego_code: str, input_data: Dict, package_name: str) -> Tuple[bool, List[str]]:
    """Execute a Rego rule with given input data.
    
    Returns:
        (denies, results) - True if rule denies, False otherwise, and list of deny messages
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rego', delete=False) as rego_file:
        # Check if rego_code already has a package declaration
        if rego_code.strip().startswith('package '):
            # Use the code as-is (it already has package declaration)
            full_rego = rego_code
        else:
            # Wrap the rule in a package
            full_rego = f"""package {package_name}

import rego.v1

{rego_code}
"""
        rego_file.write(full_rego)
        rego_file.flush()
        
        # Execute with OPA
        try:
            # Write input to temp file (OPA doesn't handle stdin well on all systems)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
                json.dump(input_data, input_file)
                input_file.flush()
                
                result = subprocess.run(
                    ['opa', 'eval', '-d', rego_file.name, '-i', input_file.name, f'data.{package_name}.deny'],
                    text=True,
                    capture_output=True,
                    timeout=5
                )
                
                Path(input_file.name).unlink()
            
            if result.returncode != 0:
                return False, []
            
            # Parse output
            output = json.loads(result.stdout)
            if 'result' in output and output['result']:
                expressions = output['result'][0].get('expressions', [])
                if expressions:
                    deny_value = expressions[0].get('value', [])
                    if isinstance(deny_value, list) and len(deny_value) > 0:
                        return True, deny_value if isinstance(deny_value[0], str) else []
            
            return False, []
        except Exception as e:
            print(f"Error executing Rego: {e}")
            return False, []
        finally:
            Path(rego_file.name).unlink()

def generate_test_variations(test_case: Dict, case_id: str) -> List[Tuple[str, Dict]]:
    """Generate candidate test data variations based on natural language, keys_used, and rego_code.
    
    Returns list of (variation_name, test_data) tuples.
    """
    natural_language = test_case["natural_language"]
    keys_used = test_case.get("keys_used", [])
    rego_code = test_case.get("rego_code", "")
    nl_lower = natural_language.lower()
    
    is_spdx = "spdx" in case_id.lower() or any("spdx" in str(k).lower() for k in keys_used)
    is_cyclonedx = "cyclonedx" in case_id.lower() or any("cyclonedx" in str(k).lower() for k in keys_used)
    
    # Check for "at least N" pattern early (used in multiple places)
    import re
    at_least_match = re.search(r'at least (\d+)', nl_lower)
    
    variations = []
    
    # Base valid attestation (should pass)
    if is_spdx:
        base = create_base_spdx_attestation()
    else:
        base = create_base_cyclonedx_attestation()
    
    # Note: base_valid will be added at the end, after all modifications
    # This allows us to modify base for specific requirements (e.g., "at least N" refs)
    
    # ========================================================================
    # Pattern 1: Collection emptiness (packages, components, files)
    # ========================================================================
    if ("contains packages" in nl_lower or "has packages" in nl_lower) and is_spdx:
        var = json.loads(json.dumps(base))
        var["statement"]["predicate"]["packages"] = []
        variations.append(("no_packages", var))
    
    if ("contains components" in nl_lower or "has components" in nl_lower) and is_cyclonedx:
        var = json.loads(json.dumps(base))
        var["statement"]["predicate"]["components"] = []
        variations.append(("no_components", var))
    
    if ("contains files" in nl_lower or "has files" in nl_lower) and is_spdx:
        var = json.loads(json.dumps(base))
        var["statement"]["predicate"]["files"] = []
        variations.append(("no_files", var))
        # Also ensure base_valid has at least one file for pass test
        base["statement"]["predicate"]["files"] = [{
            "SPDXID": "SPDXRef-File-test-1",
            "fileName": "test.txt",
            "checksums": [{"algorithm": "SHA256", "checksumValue": "a" * 64}]
        }]
    
    # ========================================================================
    # Pattern 1.5: "No packages have X" where X is a specific value (e.g., "(devel)")
    # ========================================================================
    if "no " in nl_lower and "have " in nl_lower and ("'" in natural_language or '"' in natural_language):
        import re
        # Match patterns like "have version '(devel)'" or "have X 'value'"
        value_match = re.search(r"have\s+\w+\s+['\"]([^'\"]+)['\"]", nl_lower)
        if value_match:
            forbidden_value = value_match.group(1)
            for key in keys_used:
                key_str = str(key)
                if "pkg." in key_str and is_spdx:
                    field_name = key_str.split(".")[-1]
                    var = json.loads(json.dumps(base))
                    var["statement"]["predicate"]["packages"][0][field_name] = forbidden_value
                    variations.append((f"{field_name}_equals_{forbidden_value.replace('(', '_').replace(')', '_').replace('-', '_')}", var))
                    break
    
    # ========================================================================
    # Pattern 2: Field presence ("have a <field>" or "have <field>")
    # ========================================================================
    if ("have a " in nl_lower or "have " in nl_lower):
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                pkg = var["statement"]["predicate"]["packages"][0]
                
                # Check if rule checks for == "NOASSERTION" (meaning field should NOT be "NOASSERTION")
                # Check both exact field name match and general pattern (in case of whitespace variations)
                if rego_code and ('== "NOASSERTION"' in rego_code or f'{field_name} == "NOASSERTION"' in rego_code or f'pkg.{field_name} == "NOASSERTION"' in rego_code):
                    # Rule denies when field equals "NOASSERTION", so test with "NOASSERTION"
                    pkg[field_name] = "NOASSERTION"
                    variations.append((f"{field_name}_equals_noassertion", var))
                    
                    # Also create a valid value variation for pass test
                    var_valid = copy.deepcopy(base)
                    if is_spdx:
                        pkg_valid = var_valid["statement"]["predicate"]["packages"][0]
                    else:
                        pkg_valid = var_valid["statement"]["predicate"]["components"][0]
                    
                    # Set a valid value based on field type
                    if field_name == "supplier":
                        pkg_valid[field_name] = "Organization: Test Supplier"
                    elif field_name == "licenseDeclared":
                        pkg_valid[field_name] = "MIT"
                    elif field_name == "copyrightText":
                        pkg_valid[field_name] = "Copyright (c) 2024 Test"
                    else:
                        pkg_valid[field_name] = f"Valid{field_name.capitalize()}"
                    variations.append((f"{field_name}_valid_value", var_valid))
                elif "externalRefs" in field_name and rego_code and 'count([ref' in rego_code and 'ref.referenceType == "purl"' in rego_code:
                    # Rule checks for count of purl refs == 0, so test with no purl refs (but refs can exist with other types)
                    if "externalRefs" not in pkg:
                        pkg["externalRefs"] = []
                    # Add a non-purl ref (so externalRefs exists but no purl)
                    pkg["externalRefs"] = [{
                        "referenceCategory": "SECURITY",
                        "referenceType": "cpe23Type",
                        "referenceLocator": "cpe:2.3:a:test:package:1.0.0:*:*:*:*:*:*:*"
                    }]
                    variations.append((f"no_purl_external_refs", var))
                elif field_name in pkg:
                    # Default: missing field
                    del pkg[field_name]
                    variations.append((f"missing_{field_name}", var))
                break
            elif "file." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                # Always include fileName for rules that access file.fileName
                var["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    "fileName": "test.txt"  # Required for rules that access file.fileName
                }]
                if field_name != "SPDXID" and field_name not in var["statement"]["predicate"]["files"][0]:
                    variations.append((f"file_missing_{field_name}", var))
                break
            elif "comp." in key_str and is_cyclonedx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                comp = var["statement"]["predicate"]["components"][0]
                if field_name in comp:
                    del comp[field_name]
                    variations.append((f"comp_missing_{field_name}", var))
                # Also ensure base_valid has the field for pass test
                base_comp = base["statement"]["predicate"]["components"][0]
                if field_name not in base_comp:
                    # Add default value based on field name
                    if field_name == "cpe":
                        base_comp[field_name] = "cpe:2.3:a:test:component:1.0.0:*:*:*:*:*:*:*"
                    else:
                        base_comp[field_name] = "default-value"
                break
    
    # ========================================================================
    # Pattern 3: Format validation
    # ========================================================================
    if "format" in nl_lower or (rego_code and "startswith" in rego_code.lower()) or ("valid" in nl_lower and "format" in nl_lower):
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                
                if "supplier" in field_name or "originator" in field_name:
                    # Should contain ":" but doesn't (based on rego_code)
                    if 'not contains' in rego_code and '":"' in rego_code:
                        var["statement"]["predicate"]["packages"][0][field_name] = "InvalidFormat"
                        variations.append((f"invalid_{field_name}_format", var))
                elif "spdxid" in field_name.lower():
                    # Invalid SPDXID format (should start with SPDXRef-)
                    var["statement"]["predicate"]["packages"][0][field_name] = "InvalidID"
                    variations.append((f"invalid_{field_name}_format", var))
                elif "license" in field_name.lower():
                    # License format validation (check rego_code for specifics)
                    if "LicenseRef-" in rego_code:
                        # Should start with LicenseRef- or contain "-", but doesn't
                        var["statement"]["predicate"]["packages"][0][field_name] = "MIT"  # Simple ID, no dash
                        variations.append((f"invalid_{field_name}_format", var))
                break
            elif "file." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                if "spdxid" in field_name.lower():
                    var = json.loads(json.dumps(base))
                    var["statement"]["predicate"]["files"] = [{
                        "SPDXID": "InvalidID",
                        "fileName": "test.txt"
                    }]
                    variations.append((f"file_invalid_{field_name}_format", var))
                break
    
    # ========================================================================
    # Pattern 4: Empty string validation
    # ========================================================================
    if "empty" in nl_lower or "non-empty" in nl_lower:
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                var["statement"]["predicate"]["packages"][0][field_name] = ""
                variations.append((f"empty_{field_name}", var))
                break
            elif "file." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                var["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    field_name: ""
                }]
                variations.append((f"file_empty_{field_name}", var))
                break
            elif "sbom." in key_str or "document" in key_str.lower():
                if is_spdx:
                    field_name = key_str.split(".")[-1] if "." in key_str else key_str
                    var = json.loads(json.dumps(base))
                    if field_name in var["statement"]["predicate"]:
                        var["statement"]["predicate"][field_name] = ""
                        variations.append((f"sbom_empty_{field_name}", var))
                    break
    
    # ========================================================================
    # Pattern 5: Uniqueness validation
    # ========================================================================
    if "unique" in nl_lower or "duplicate" in nl_lower:
        if is_spdx and "package" in nl_lower:
            var = json.loads(json.dumps(base))
            # Add duplicate SPDXID
            pkg2 = json.loads(json.dumps(var["statement"]["predicate"]["packages"][0]))
            var["statement"]["predicate"]["packages"].append(pkg2)  # Same SPDXID
            variations.append(("duplicate_package_spdxid", var))
        elif is_spdx and "file" in nl_lower:
            var = json.loads(json.dumps(base))
            var["statement"]["predicate"]["files"] = [
                {"SPDXID": "SPDXRef-File-test-1", "fileName": "file1.txt"},
                {"SPDXID": "SPDXRef-File-test-1", "fileName": "file2.txt"}  # Duplicate
            ]
            variations.append(("duplicate_file_spdxid", var))
        elif is_spdx and "checksum" in nl_lower and "algorithm" in nl_lower:
            var = json.loads(json.dumps(base))
            # Duplicate checksum algorithms
            if "pkg." in str(keys_used):
                var["statement"]["predicate"]["packages"][0]["checksums"] = [
                    {"algorithm": "SHA256", "checksumValue": "a" * 64},
                    {"algorithm": "SHA256", "checksumValue": "b" * 64}  # Duplicate algorithm
                ]
                variations.append(("duplicate_checksum_algorithm", var))
            elif "file." in str(keys_used):
                var["statement"]["predicate"]["files"] = [{
                    "SPDXID": "SPDXRef-File-test-1",
                    "fileName": "test.txt",
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": "a" * 64},
                        {"algorithm": "SHA256", "checksumValue": "b" * 64}  # Duplicate
                    ]
                }]
                variations.append(("file_duplicate_checksum_algorithm", var))
    
    # ========================================================================
    # Pattern 6: Count/at least validation
    # ========================================================================
    if "count" in nl_lower or "at least" in nl_lower:
        if is_spdx and "package" in nl_lower:
            var = json.loads(json.dumps(base))
            var["statement"]["predicate"]["packages"] = []  # Zero packages
            variations.append(("zero_packages", var))
        elif is_spdx and "file" in nl_lower:
            var = json.loads(json.dumps(base))
            var["statement"]["predicate"]["files"] = []  # Zero files
            variations.append(("zero_files", var))
        elif is_cyclonedx and "component" in nl_lower:
            var = json.loads(json.dumps(base))
            var["statement"]["predicate"]["components"] = []  # Zero components
            variations.append(("zero_components", var))
    
    # ========================================================================
    # Pattern 7: Checksum presence/validation
    # ========================================================================
    if "checksum" in nl_lower:
        for key in keys_used:
            key_str = str(key)
            if "checksum" in key_str.lower() and is_spdx:
                # Check if it's a checksumValue check (nested field in checksums array)
                if "checksumvalue" in nl_lower or "checksumValue" in key_str:
                    # Rule checks for checksumValue in checksums - create file with checksum missing checksumValue
                    var = json.loads(json.dumps(base))
                    var["statement"]["predicate"]["files"] = [{
                        "SPDXID": "SPDXRef-File-test-1",
                        "fileName": "test.txt",
                        "checksums": [{
                            "algorithm": "SHA256"
                            # Missing checksumValue
                        }]
                    }]
                    variations.append(("file_checksum_missing_checksumvalue", var))
                else:
                    var = json.loads(json.dumps(base))
                    if "pkg." in key_str:
                        var["statement"]["predicate"]["packages"][0]["checksums"] = []
                        variations.append(("no_checksums", var))
                    elif "file." in key_str:
                        var["statement"]["predicate"]["files"] = [{
                            "SPDXID": "SPDXRef-File-test-1",
                            "fileName": "test.txt"
                            # No checksums
                        }]
                        variations.append(("file_no_checksums", var))
                break
    
    # ========================================================================
    # Pattern 8: Not equal validation ("not equal to", "!=")
    # ========================================================================
    if "not equal" in nl_lower or (rego_code and "!=" in rego_code):
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                # Check what value it should not equal
                if '"NOASSERTION"' in rego_code:
                    var["statement"]["predicate"]["packages"][0][field_name] = "NOASSERTION"
                    variations.append((f"{field_name}_equals_noassertion", var))
                elif '""' in rego_code or '== ""' in rego_code:
                    # Should not be empty, so set to empty
                    var["statement"]["predicate"]["packages"][0][field_name] = ""
                    variations.append((f"{field_name}_empty", var))
                # Check for boolean validation: field != true AND field != false
                # OR natural language says "set to boolean" (meaning must be boolean, not other type)
                elif (rego_code and "!= true" in rego_code and "!= false" in rego_code) or "boolean" in nl_lower:
                    # Field should be a non-boolean value (e.g., string, number)
                    # Ensure field exists but with invalid type
                    var["statement"]["predicate"]["packages"][0][field_name] = "invalid"
                    variations.append((f"{field_name}_invalid_boolean", var))
                break
    
    # ========================================================================
    # Pattern 9: Startswith validation
    # ========================================================================
    if (rego_code and "startswith" in rego_code.lower()) or "starts with" in nl_lower or ("format" in nl_lower and "spdxid" in nl_lower):
        import re
        # Find "not startswith" patterns (more specific, check first)
        not_startswith_patterns = re.finditer(r'not\s+startswith\([^,)]+,\s*"([^"]+)"\)', rego_code)
        not_startswith_matches = [m.group(1) for m in not_startswith_patterns]
        
        # Find regular "startswith" patterns (not preceded by "not")
        startswith_patterns = re.finditer(r'(?<!not\s)startswith\([^,)]+,\s*"([^"]+)"\)', rego_code)
        startswith_matches = [m.group(1) for m in startswith_patterns]
        
        # Check for external reference startswith FIRST (before package field checks)
        ref_keys = [k for k in keys_used if "ref." in str(k)]
        if ref_keys and is_spdx:
            # Find which field is being checked (referenceLocator, etc.)
            ref_locator_key = next((k for k in ref_keys if "referenceLocator" in str(k) or "Locator" in str(k)), ref_keys[0])
            field_name = str(ref_locator_key).split(".")[-1]  # e.g., "referenceLocator"
            var = json.loads(json.dumps(base))
            pkg = var["statement"]["predicate"]["packages"][0]
            
            # Check what referenceType is expected from rego_code
            ref_type_match = re.search(r'ref\.referenceType\s*==\s*"([^"]+)"', rego_code)
            expected_ref_type = ref_type_match.group(1) if ref_type_match else "purl"
            
            # Ensure externalRefs exist with correct type
            if "externalRefs" not in pkg or not pkg["externalRefs"]:
                pkg["externalRefs"] = [{
                    "referenceCategory": "PACKAGE_MANAGER",
                    "referenceType": expected_ref_type,
                    "referenceLocator": f"{startswith_matches[0] if startswith_matches else 'pkg:'}rpm/test-package@1.0.0"
                }]
            else:
                # Update existing ref to have correct type
                pkg["externalRefs"][0]["referenceType"] = expected_ref_type
            
            refs = pkg["externalRefs"]
            if refs:
                if not_startswith_matches:
                    prefix = not_startswith_matches[0]
                    # Rule denies when: ref.referenceType == "purl" AND not startswith(ref.referenceLocator, "pkg:")
                    # So we need referenceLocator that does NOT start with prefix
                    refs[0][field_name] = f"invalid{prefix}"  # Doesn't start with prefix
                    variations.append((f"external_ref_{field_name}_not_starts_with_{prefix.replace(':', '_')}", var))
                elif startswith_matches:
                    prefix = startswith_matches[0]
                    # Rule requires startswith, so set to value that doesn't start with prefix
                    refs[0][field_name] = f"invalid{prefix}"
                    variations.append((f"external_ref_{field_name}_not_starts_with_{prefix.replace(':', '_')}", var))
        
        # Then check package fields
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str and is_spdx and "ref." not in key_str:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                
                # Check if it's "not startswith" (should NOT start with prefix)
                if not_startswith_matches:
                    prefix = not_startswith_matches[0]
                    # Set to value that DOES start with prefix (violates "not startswith")
                    var["statement"]["predicate"]["packages"][0][field_name] = f"{prefix}value"
                    variations.append((f"{field_name}_starts_with_{prefix.replace('-', '_').replace(':', '_')}", var))
                elif startswith_matches:
                    prefix = startswith_matches[0]
                    # Set to value that doesn't start with prefix
                    var["statement"]["predicate"]["packages"][0][field_name] = f"invalid{prefix}"
                    variations.append((f"{field_name}_not_starts_with_{prefix.replace('-', '_').replace(':', '_')}", var))
                break
            elif "sbom." in key_str or "document" in key_str.lower():
                if is_spdx:
                    field_name = key_str.split(".")[-1] if "." in key_str else key_str
                    var = json.loads(json.dumps(base))
                    if not_startswith_matches:
                        prefix = not_startswith_matches[0]
                        var["statement"]["predicate"][field_name] = f"{prefix}value"
                        variations.append((f"sbom_{field_name}_starts_with_{prefix.replace('-', '_').replace(':', '_')}", var))
                    elif startswith_matches:
                        prefix = startswith_matches[0]
                        var["statement"]["predicate"][field_name] = f"invalid{prefix}"
                        variations.append((f"sbom_{field_name}_not_starts_with_{prefix.replace('-', '_').replace(':', '_')}", var))
                    break
    
    # ========================================================================
    # Pattern 10: Contains function validation
    # ========================================================================
    if "contains(" in rego_code.lower():
        import re
        # Find all contains() calls
        contains_matches = re.findall(r'contains\([^,)]+,\s*"([^"]+)"\)', rego_code)
        not_contains_matches = re.findall(r'not\s+contains\([^,)]+,\s*"([^"]+)"\)', rego_code)
        
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                
                # Check if it's "not contains" (should NOT contain substring)
                if not_contains_matches:
                    substring = not_contains_matches[0]
                    # Set to value that DOES contain substring (violates "not contains")
                    var["statement"]["predicate"]["packages"][0][field_name] = f"Value{substring}Here"
                    variations.append((f"{field_name}_contains_{substring.replace(':', '_').replace('-', '_')}", var))
                elif contains_matches:
                    substring = contains_matches[0]
                    # Set to value that doesn't contain substring
                    var["statement"]["predicate"]["packages"][0][field_name] = f"ValueWithout{substring}"
                    variations.append((f"{field_name}_not_contains_{substring.replace(':', '_').replace('-', '_')}", var))
                break
    
    # ========================================================================
    # Pattern 11: Conditional validation (field == true AND not other_field)
    # ========================================================================
    if "== true" in rego_code and "not " in rego_code:
        for key in keys_used:
            key_str = str(key)
            if "pkg." in key_str and is_spdx:
                # Find the field that should be true
                import re
                true_field_match = re.search(r'pkg\.(\w+)\s*==\s*true', rego_code)
                not_field_match = re.search(r'not\s+pkg\.(\w+)', rego_code)
                if true_field_match and not_field_match:
                    true_field = true_field_match.group(1)
                    not_field = not_field_match.group(1)
                    var = json.loads(json.dumps(base))
                    var["statement"]["predicate"]["packages"][0][true_field] = True
                    if not_field in var["statement"]["predicate"]["packages"][0]:
                        del var["statement"]["predicate"]["packages"][0][not_field]
                    variations.append((f"{true_field}_true_but_missing_{not_field}", var))
                break
    
    # ========================================================================
    # Pattern 12: Nested field validation (pkg.field.field)
    # ========================================================================
    for key in keys_used:
        key_str = str(key)
        if key_str.count(".") >= 2 and is_spdx:  # Nested field like pkg.field.subfield
            parts = key_str.split(".")
            if "pkg." in key_str:
                field1 = parts[1]
                field2 = parts[2]
                var = json.loads(json.dumps(base))
                pkg = var["statement"]["predicate"]["packages"][0]
                if field1 not in pkg:
                    pkg[field1] = {}
                if "empty" in nl_lower or '== ""' in rego_code:
                    pkg[field1][field2] = ""
                    variations.append((f"{field1}_{field2}_empty", var))
                break
    
    # ========================================================================
    # Pattern 13: External references validation
    # ========================================================================
    if "external" in nl_lower or "externalRefs" in str(keys_used):
        if is_spdx:
            var = json.loads(json.dumps(base))
            pkg = var["statement"]["predicate"]["packages"][0]
            
            # Try missing externalRefs
            if "externalRefs" in pkg:
                del pkg["externalRefs"]
                variations.append(("no_external_refs", var))
            
            # Try empty externalRefs
            var2 = json.loads(json.dumps(base))
            var2["statement"]["predicate"]["packages"][0]["externalRefs"] = []
            variations.append(("empty_external_refs", var2))
            
            # Try invalid externalRef fields
            var4 = json.loads(json.dumps(base))
            if var4["statement"]["predicate"]["packages"][0]["externalRefs"]:
                ref = var4["statement"]["predicate"]["packages"][0]["externalRefs"][0]
                if "referenceType" in ref:
                    ref["referenceType"] = "invalid"
                    variations.append(("invalid_external_ref_type", var4))
                if "referenceLocator" in ref:
                    ref["referenceLocator"] = "invalid"
                    variations.append(("invalid_external_ref_locator", var4))
            
            # Check for specific referenceType checks (e.g., "cpe23Type", "purl", etc.)
            # If natural language mentions a specific type that should not exist
            if "no " in nl_lower or "not " in nl_lower or "disallow" in nl_lower:
                # Check for specific forbidden types mentioned in natural language
                import re
                # Try to match "type 'cpe23Type'" or "type \"cpe23Type\"" or "type cpe23Type"
                # First try to match quoted type (most common)
                type_match = re.search(r"type\s+['\"]([^'\"]+)['\"]", natural_language, re.IGNORECASE)
                if type_match:
                    # Extract from original string to preserve case
                    start_pos = natural_language.lower().find(type_match.group(0).lower())
                    if start_pos != -1:
                        original_match = natural_language[start_pos:start_pos+len(type_match.group(0))]
                        forbidden_type_match = re.search(r"['\"]([^'\"]+)['\"]", original_match)
                        if forbidden_type_match:
                            forbidden_type = forbidden_type_match.group(1)
                        else:
                            forbidden_type = type_match.group(1)
                    else:
                        forbidden_type = type_match.group(1)
                else:
                    # Fallback: try unquoted type
                    type_match = re.search(r"type\s+([a-zA-Z0-9]+)", natural_language, re.IGNORECASE)
                    if type_match:
                        start_pos = natural_language.lower().find(type_match.group(0).lower())
                        if start_pos != -1:
                            original_match = natural_language[start_pos:start_pos+len(type_match.group(0))]
                            forbidden_type_match = re.search(r"type\s+([a-zA-Z0-9]+)", original_match, re.IGNORECASE)
                            if forbidden_type_match:
                                forbidden_type = forbidden_type_match.group(1)
                            else:
                                forbidden_type = type_match.group(1)
                        else:
                            forbidden_type = type_match.group(1)
                    else:
                        forbidden_type = None
                
                if forbidden_type:
                    var_forbidden = json.loads(json.dumps(base))
                    pkg_forbidden = var_forbidden["statement"]["predicate"]["packages"][0]
                    # Ensure externalRefs exist with the forbidden type
                    if "externalRefs" not in pkg_forbidden:
                        pkg_forbidden["externalRefs"] = []
                    # Replace existing refs with the forbidden type
                    pkg_forbidden["externalRefs"] = [{
                        "referenceCategory": "SECURITY",
                        "referenceType": forbidden_type,
                        "referenceLocator": "cpe:2.3:a:test:package:1.0.0:*:*:*:*:*:*:*" if "cpe" in forbidden_type.lower() else "pkg:rpm/test-package@1.0.0"
                    }]
                    variations.append((f"has_forbidden_ref_type_{forbidden_type.lower()}", var_forbidden))
            
            # For "at least N" checks, create variations with fewer than N refs
            if at_least_match:
                min_count = int(at_least_match.group(1))
                # Create variation with exactly (min_count - 1) refs (should deny)
                var_count = json.loads(json.dumps(base))
                pkg_count = var_count["statement"]["predicate"]["packages"][0]
                if min_count - 1 == 0:
                    # Use empty array for count() to work
                    pkg_count["externalRefs"] = []
                    variations.append(("empty_external_refs", var_count))
                else:
                    pkg_count["externalRefs"] = [
                        {"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:rpm/test-package-{i}@1.0.0"}
                        for i in range(min_count - 1)
                    ]
                    variations.append((f"external_refs_count_{min_count - 1}", var_count))
                
                # Update base to have at least min_count refs (should pass)
                base_pkg = base["statement"]["predicate"]["packages"][0]
                base_pkg["externalRefs"] = [
                    {"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": f"pkg:rpm/test-package-{i}@1.0.0"}
                    for i in range(min_count)
                ]
    
    # ========================================================================
    # Pattern 14: Timestamp/date validation
    # ========================================================================
    if "timestamp" in nl_lower or "date" in nl_lower or "created" in nl_lower or "time" in nl_lower:
        if is_spdx:
            # Check if rule checks for field presence (not field) vs format validation
            # If "has" or "with" is in natural language, it's a presence check
            if "has" in nl_lower or "with" in nl_lower:
                # Rule checks for field presence - test with missing field
                var = json.loads(json.dumps(base))
                if "creationInfo" in var["statement"]["predicate"]:
                    if "created" in var["statement"]["predicate"]["creationInfo"]:
                        del var["statement"]["predicate"]["creationInfo"]["created"]
                        variations.append(("missing_created_timestamp", var))
            else:
                # Rule checks for format - test with invalid format
                var = json.loads(json.dumps(base))
                if "creationInfo" in var["statement"]["predicate"]:
                    # Invalid timestamp format
                    var["statement"]["predicate"]["creationInfo"]["created"] = "invalid-date"
                    variations.append(("invalid_timestamp", var))
        elif is_cyclonedx:
            var = json.loads(json.dumps(base))
            if "metadata" in var["statement"]["predicate"] and "timestamp" in var["statement"]["predicate"]["metadata"]:
                var["statement"]["predicate"]["metadata"]["timestamp"] = "invalid-date"
                variations.append(("invalid_timestamp", var))
    
    # ========================================================================
    # Pattern 15: Generic fallback - try common modifications
    # ========================================================================
    if len(variations) == 1:  # Only base_valid, try generic modifications
        for key in keys_used[:5]:  # Try first 5 keys
            key_str = str(key)
            if "pkg." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                pkg = var["statement"]["predicate"]["packages"][0]
                if field_name in pkg:
                    # Try 1: Remove field
                    var1 = json.loads(json.dumps(var))
                    del var1["statement"]["predicate"]["packages"][0][field_name]
                    variations.append((f"missing_{field_name}", var1))
                    
                    # Try 2: Set to empty
                    var2 = json.loads(json.dumps(var))
                    var2["statement"]["predicate"]["packages"][0][field_name] = ""
                    variations.append((f"empty_{field_name}", var2))
                    
                    # Try 3: Set to invalid value
                    var3 = json.loads(json.dumps(var))
                    var3["statement"]["predicate"]["packages"][0][field_name] = "INVALID"
                    variations.append((f"invalid_{field_name}", var3))
                break
            elif "file." in key_str and is_spdx:
                field_name = key_str.split(".")[-1]
                var = json.loads(json.dumps(base))
                var["statement"]["predicate"]["files"] = [{"SPDXID": "SPDXRef-File-test-1"}]
                if field_name != "SPDXID":
                    if field_name not in var["statement"]["predicate"]["files"][0]:
                        variations.append((f"file_missing_{field_name}", var))
                    else:
                        var2 = json.loads(json.dumps(var))
                        var2["statement"]["predicate"]["files"][0][field_name] = ""
                        variations.append((f"file_empty_{field_name}", var2))
                break
            elif "sbom." in key_str or "document" in key_str.lower():
                if is_spdx:
                    field_name = key_str.split(".")[-1] if "." in key_str else key_str
                    var = json.loads(json.dumps(base))
                    if field_name in var["statement"]["predicate"]:
                        var["statement"]["predicate"][field_name] = "INVALID"
                        variations.append((f"sbom_invalid_{field_name}", var))
                    break
    
    # Add base_valid at the end (after all modifications)
    # Use the modified base (e.g., if externalRefs count was increased for "at least N")
    variations.append(("base_valid", base))
    
    return variations

def generate_tests_from_requirements(test_case: Dict, case_id: str) -> List[Dict]:
    """Generate tests from requirements only (TDD workflow - no rego_code needed).
    
    Uses pattern matching on natural_language and keys_used to generate test data.
    Tests are generated without executing rules - rules will be generated later to make tests pass.
    """
    # Generate test variations from requirements
    variations = generate_test_variations(test_case, case_id)
    
    positive_tests = []  # Should deny
    negative_tests = []   # Should pass
    
    # Classify variations based on natural language and patterns
    for var_name, test_data in variations:
        input_data = {"attestations": [test_data]}
        
        # Determine if this should deny or pass based on variation name and natural language
        should_deny = determine_should_deny(var_name, test_case, case_id)
        
        test_entry = {
            "name": f"test_{var_name}",
            "input": input_data,
            "should_deny": should_deny
        }
        
        if should_deny:
            positive_tests.append(test_entry)
        else:
            negative_tests.append(test_entry)
    
    # Ensure we have at least one positive and one negative test
    tests = []
    
    if positive_tests:
        # Prioritize variations for count checks
        nl_lower = test_case["natural_language"].lower()
        if "count" in nl_lower or "at least" in nl_lower:
            # Prefer count_ variations (e.g., external_refs_count_1) for "at least N" checks
            # Then empty_ variations, then others
            count_test = next((t for t in positive_tests if "count_" in t["name"] or "external_refs_count_" in t["name"]), None)
            if count_test:
                pos_test = count_test
            else:
                empty_test = next((t for t in positive_tests if "empty_" in t["name"]), None)
                if empty_test:
                    pos_test = empty_test
                else:
                    pos_test = positive_tests[0]
        elif "forbidden" in nl_lower or "disallow" in nl_lower or ("no " in nl_lower and "type" in nl_lower):
            # For forbidden type checks, prefer has_forbidden_ref_type variations
            forbidden_test = next((t for t in positive_tests if "forbidden" in t["name"] or "has_forbidden" in t["name"]), None)
            if forbidden_test:
                pos_test = forbidden_test
            else:
                pos_test = positive_tests[0]
        elif "no " in nl_lower and "have " in nl_lower:
            # For "no packages have X" checks (specific value), prefer equals_<value> variations
            equals_test = next((t for t in positive_tests if "equals_" in t["name"]), None)
            if equals_test:
                pos_test = equals_test
            else:
                pos_test = positive_tests[0]
        elif "have a " in nl_lower or "have " in nl_lower:
            # For field presence checks, prefer missing_<field> variations
            missing_test = next((t for t in positive_tests if "missing_" in t["name"]), None)
            if missing_test:
                pos_test = missing_test
            else:
                pos_test = positive_tests[0]
        elif "sha256" in nl_lower or "checksum" in nl_lower:
            # For checksum checks, prefer file_checksum_missing_checksumvalue, then file_no_sha256, then file_no_checksums
            checksumvalue_test = next((t for t in positive_tests if "checksumvalue" in t["name"] or "missing_checksumvalue" in t["name"]), None)
            if checksumvalue_test:
                pos_test = checksumvalue_test
            else:
                checksum_test = next((t for t in positive_tests if "sha256" in t["name"] or "checksum" in t["name"]), None)
                if checksum_test:
                    pos_test = checksum_test
                else:
                    pos_test = positive_tests[0]
        elif "boolean" in nl_lower:
            # For boolean validation, prefer invalid_<field> variations (created by Pattern 8)
            boolean_test = next((t for t in positive_tests if "invalid_" in t["name"]), None)
            if boolean_test:
                pos_test = boolean_test
            else:
                pos_test = positive_tests[0]
        elif "format" in nl_lower or ("valid" in nl_lower and "format" in nl_lower):
            # For format validation, prefer invalid_format variations
            format_test = next((t for t in positive_tests if "format" in t["name"] or "invalid" in t["name"]), None)
            if format_test:
                pos_test = format_test
            else:
                pos_test = positive_tests[0]
        elif "have a " in nl_lower or "have " in nl_lower:
            # For field presence checks, prefer missing_<field> variations
            missing_test = next((t for t in positive_tests if "missing_" in t["name"]), None)
            if missing_test:
                pos_test = missing_test
            else:
                pos_test = positive_tests[0]
        else:
            pos_test = positive_tests[0]
        pos_test["name"] = "should_deny_when_condition_violated"
        tests.append(pos_test)
    
    if negative_tests:
        neg_test = next((t for t in negative_tests if "base_valid" in t["name"]), negative_tests[0])
        neg_test["name"] = "should_pass_when_condition_met"
        tests.append(neg_test)
    
    return tests

def determine_should_deny(var_name: str, test_case: Dict, case_id: str) -> bool:
    """Determine if a test variation should deny based on its name and natural language."""
    nl_lower = test_case["natural_language"].lower()
    
    # Patterns that indicate should deny
    deny_patterns = [
        "no_", "missing_", "empty_", "invalid_", "zero_", "duplicate_",
        "not_", "without_", "lacks_", "count_"
    ]
    
    # Patterns that indicate should pass
    pass_patterns = ["base_valid", "valid_", "contains_"]
    
    # Special case: "has_forbidden" should deny (not pass)
    if "has_forbidden" in var_name or "forbidden" in var_name:
        # Check if this is a forbidden type check
        if "forbidden" in nl_lower or "disallow" in nl_lower or ("no " in nl_lower and "type" in nl_lower):
            return True
    
    # Check variation name
    if any(pattern in var_name for pattern in deny_patterns):
        return True
    if any(pattern in var_name for pattern in pass_patterns):
        return False
    # "has_" is only a pass pattern if not "has_forbidden"
    if "has_" in var_name and "forbidden" not in var_name:
        return False
    
    # Check natural language for context
    if "no " in nl_lower or "missing" in nl_lower or "empty" in nl_lower:
        if "no_" in var_name or "missing_" in var_name or "empty_" in var_name:
            return True
    
    # For "at least" checks, empty or count < N should deny
    if "at least" in nl_lower:
        if "empty_" in var_name or "count_" in var_name or "external_refs_count_" in var_name:
            return True
    
    # For forbidden type checks, has_forbidden_ref_type should deny
    if "forbidden" in nl_lower or "disallow" in nl_lower or ("no " in nl_lower and "type" in nl_lower):
        if "has_forbidden" in var_name or "forbidden" in var_name:
            return True
    
    # Default: base_valid should pass, others might deny
    return "base_valid" not in var_name

def generate_tests_by_execution(test_case: Dict, case_id: str) -> List[Dict]:
    """Generate tests by executing the Rego rule with different test data (legacy workflow)."""
    rego_code = test_case.get("rego_code", "")
    if not rego_code:
        return []
    
    # Extract package name from rego_code or use case_id
    package_name = case_id.replace("-", "_")
    
    # Generate test variations
    variations = generate_test_variations(test_case, case_id)
    
    positive_tests = []  # Should deny
    negative_tests = []   # Should pass
    
    # Execute all variations
    for var_name, test_data in variations:
        input_data = {"attestations": [test_data]}
        denies, messages = execute_rego_rule(rego_code, input_data, package_name)
        
        test_entry = {
            "name": f"test_{var_name}",
            "input": input_data,
            "should_deny": denies
        }
        
        if denies:
            positive_tests.append(test_entry)
        else:
            negative_tests.append(test_entry)
    
    # If we don't have positive tests, try more aggressive variations
    if not positive_tests:
        # Try generating more variations based on rego_code analysis
        additional_variations = generate_additional_variations(test_case, case_id)
        for var_name, test_data in additional_variations:
            input_data = {"attestations": [test_data]}
            denies, messages = execute_rego_rule(rego_code, input_data, package_name)
            
            if denies:
                test_entry = {
                    "name": f"test_{var_name}",
                    "input": input_data,
                    "should_deny": True
                }
                positive_tests.append(test_entry)
                break  # Found one, that's enough
    
    # Ensure we have at least one positive and one negative test
    tests = []
    
    if positive_tests:
        # Prioritize variations based on Rego code patterns
        nl_lower = test_case.get("natural_language", "").lower()
        
        # Check if rule checks for == "NOASSERTION" (Pattern 2 special case)
        if rego_code and '== "NOASSERTION"' in rego_code:
            # Prioritize equals_noassertion variations
            equals_test = next((t for t in positive_tests if "equals_noassertion" in t["name"]), None)
            if equals_test:
                pos_test = equals_test
            else:
                pos_test = positive_tests[0]
        elif "count" in nl_lower or "at least" in nl_lower:
            # Prefer count_ variations for "at least N" checks
            count_test = next((t for t in positive_tests if "count_" in t["name"] or "external_refs_count_" in t["name"]), None)
            if count_test:
                pos_test = count_test
            else:
                empty_test = next((t for t in positive_tests if "empty_" in t["name"]), None)
                if empty_test:
                    pos_test = empty_test
                else:
                    pos_test = positive_tests[0]
        elif "forbidden" in nl_lower or "disallow" in nl_lower or ("no " in nl_lower and "type" in nl_lower):
            # For forbidden type checks, prefer has_forbidden_ref_type variations
            forbidden_test = next((t for t in positive_tests if "forbidden" in t["name"] or "has_forbidden" in t["name"]), None)
            if forbidden_test:
                pos_test = forbidden_test
            else:
                pos_test = positive_tests[0]
        elif "no " in nl_lower and "have " in nl_lower:
            # For "no packages have X" checks (specific value), prefer equals_ variations
            equals_test = next((t for t in positive_tests if "equals_" in t["name"]), None)
            if equals_test:
                pos_test = equals_test
            else:
                pos_test = positive_tests[0]
        elif "boolean" in nl_lower or (rego_code and ("!= true" in rego_code or "!= false" in rego_code)):
            # For boolean validation, prefer invalid_<field> variations
            boolean_test = next((t for t in positive_tests if "invalid_" in t["name"]), None)
            if boolean_test:
                pos_test = boolean_test
            else:
                pos_test = positive_tests[0]
        elif "format" in nl_lower or ("valid" in nl_lower and "format" in nl_lower) or (rego_code and "startswith" in rego_code):
            # For format validation, prefer invalid_format variations
            format_test = next((t for t in positive_tests if "format" in t["name"] or "invalid" in t["name"]), None)
            if format_test:
                pos_test = format_test
            else:
                pos_test = positive_tests[0]
        elif "sha256" in nl_lower or "checksum" in nl_lower:
            # For checksum checks, prefer file_checksum_missing_checksumvalue, then file_no_sha256, then file_no_checksums
            checksumvalue_test = next((t for t in positive_tests if "checksumvalue" in t["name"] or "missing_checksumvalue" in t["name"]), None)
            if checksumvalue_test:
                pos_test = checksumvalue_test
            else:
                checksum_test = next((t for t in positive_tests if "sha256" in t["name"] or "checksum" in t["name"]), None)
                if checksum_test:
                    pos_test = checksum_test
                else:
                    pos_test = positive_tests[0]
        elif "have a " in nl_lower or "have " in nl_lower:
            # For field presence checks, prefer missing_<field> variations (but only if not NOASSERTION check)
            missing_test = next((t for t in positive_tests if "missing_" in t["name"]), None)
            if missing_test:
                pos_test = missing_test
            else:
                pos_test = positive_tests[0]
        else:
            pos_test = positive_tests[0]
        pos_test["name"] = "should_deny_when_condition_violated"
        tests.append(pos_test)
    else:
        # If still no positive test found, try one more time with extreme modifications
        extreme_var = try_extreme_modifications(test_case, case_id)
        if extreme_var:
            input_data = {"attestations": [extreme_var]}
            denies, messages = execute_rego_rule(rego_code, input_data, package_name)
            if denies:
                tests.append({
                    "name": "should_deny_when_condition_violated",
                    "input": input_data,
                    "should_deny": True
                })
            else:
                print(f"⚠️  Warning: No positive test found for {case_id}")
    
    if negative_tests:
        # For rules checking == "NOASSERTION", prefer valid_value variations
        if rego_code and '== "NOASSERTION"' in rego_code:
            valid_test = next((t for t in negative_tests if "valid_value" in t["name"]), None)
            if valid_test:
                neg_test = valid_test
            else:
                neg_test = next((t for t in negative_tests if "base_valid" in t["name"]), negative_tests[0])
        else:
            # Use the base valid test if available, otherwise first negative
            neg_test = next((t for t in negative_tests if "base_valid" in t["name"]), negative_tests[0])
        
        # For rules checking "not field", ensure the pass test has that field
        # For rules checking "at least N", ensure the pass test has N items
        if rego_code:
            import re
            test_input = neg_test["input"]["attestations"][0]
            
            # Check for "at least N" patterns in natural language or Rego code
            nl_lower = test_case.get("natural_language", "").lower()
            at_least_match = re.search(r'at least (\d+)', nl_lower)
            
            # Check for count patterns in Rego code
            count_patterns = [
                (r'count\(sbom\.packages\)\s*<\s*(\d+)', 'packages', int),
                (r'count\(sbom\.files\)\s*<\s*(\d+)', 'files', int),
                (r'count\(sbom\.components\)\s*<\s*(\d+)', 'components', int),
                (r'analyzed_count\s*:=\s*count\(\[.*filesAnalyzed\s*==\s*true.*\]\);.*analyzed_count\s*==\s*0', 'filesAnalyzed_true', None),
            ]
            
            for pattern, item_type, convert_func in count_patterns:
                match = re.search(pattern, rego_code, re.DOTALL)
                if match:
                    if item_type == 'filesAnalyzed_true':
                        # Ensure at least one package has filesAnalyzed: true
                        if "spdx" in case_id.lower():
                            packages = test_input["statement"]["predicate"]["packages"]
                            if packages:
                                packages[0]["filesAnalyzed"] = True
                    elif convert_func:
                        min_count = convert_func(match.group(1))
                        if "spdx" in case_id.lower():
                            sbom = test_input["statement"]["predicate"]
                            if item_type == 'packages':
                                # Ensure we have at least min_count packages
                                while len(sbom.get("packages", [])) < min_count:
                                    # Clone the first package
                                    new_pkg = json.loads(json.dumps(sbom["packages"][0]))
                                    new_pkg["SPDXID"] = f"SPDXRef-Package-test-{len(sbom['packages']) + 1}"
                                    new_pkg["name"] = f"test-package-{len(sbom['packages']) + 1}"
                                    sbom["packages"].append(new_pkg)
                            elif item_type == 'files':
                                # Ensure we have at least min_count files
                                if "files" not in sbom:
                                    sbom["files"] = []
                                while len(sbom["files"]) < min_count:
                                    new_file = {
                                        "SPDXID": f"SPDXRef-File-test-{len(sbom['files']) + 1}",
                                        "fileName": f"test-{len(sbom['files']) + 1}.txt"
                                    }
                                    sbom["files"].append(new_file)
                        elif "cyclonedx" in case_id.lower():
                            sbom = test_input["statement"]["predicate"]
                            if item_type == 'components':
                                # Ensure we have at least min_count components
                                while len(sbom.get("components", [])) < min_count:
                                    # Clone the first component
                                    new_comp = json.loads(json.dumps(sbom["components"][0]))
                                    new_comp["bom-ref"] = f"test-component-ref-{len(sbom['components']) + 1}"
                                    new_comp["name"] = f"test-component-{len(sbom['components']) + 1}"
                                    sbom["components"].append(new_comp)
                    break
            
            # Check for "not pkg.field" or "not comp.field" patterns
            not_field_match = re.search(r'not\s+(?:pkg|comp)\.(\w+)', rego_code)
            if not_field_match:
                field_name = not_field_match.group(1)
                # Ensure the pass test has this field
                if "spdx" in case_id.lower():
                    packages = test_input["statement"]["predicate"]["packages"]
                    if packages:
                        pkg = packages[0]
                        if field_name not in pkg:
                            # Add the field with a valid default value
                            if field_name == "sourceInfo":
                                pkg[field_name] = "git+https://example.com/repo.git"
                            elif field_name == "homepage":
                                pkg[field_name] = "https://example.com"
                            else:
                                pkg[field_name] = f"Valid{field_name}"
                elif "cyclonedx" in case_id.lower():
                    components = test_input["statement"]["predicate"]["components"]
                    if components:
                        comp = components[0]
                        if field_name not in comp:
                            # Add the field with a valid default value
                            comp[field_name] = f"Valid{field_name}"
        
        neg_test["name"] = "should_pass_when_condition_met"
        tests.append(neg_test)
    else:
        print(f"⚠️  Warning: No negative test found for {case_id}")
    
    return tests

def generate_additional_variations(test_case: Dict, case_id: str) -> List[Tuple[str, Dict]]:
    """Generate additional variations when initial ones don't trigger a deny."""
    natural_language = test_case["natural_language"]
    keys_used = test_case.get("keys_used", [])
    rego_code = test_case.get("rego_code", "")
    nl_lower = natural_language.lower()
    
    is_spdx = "spdx" in case_id.lower() or any("spdx" in str(k).lower() for k in keys_used)
    is_cyclonedx = "cyclonedx" in case_id.lower() or any("cyclonedx" in str(k).lower() for k in keys_used)
    
    variations = []
    
    if is_spdx:
        base = create_base_spdx_attestation()
    else:
        base = create_base_cyclonedx_attestation()
    
    # Try more aggressive modifications
    for key in keys_used:
        key_str = str(key)
        
        # Try nested field modifications
        if key_str.count(".") >= 2:
            parts = key_str.split(".")
            if "pkg." in key_str and is_spdx:
                field1 = parts[1]
                field2 = parts[2] if len(parts) > 2 else None
                var = json.loads(json.dumps(base))
                pkg = var["statement"]["predicate"]["packages"][0]
                
                if field2:
                    if field1 not in pkg:
                        pkg[field1] = {}
                    pkg[field1][field2] = ""  # Empty nested field
                    variations.append((f"nested_empty_{field1}_{field2}", var))
                else:
                    if field1 in pkg:
                        del pkg[field1]  # Missing nested object
                        variations.append((f"missing_{field1}", var))
        
        # Try array element modifications
        if "externalRefs" in key_str and is_spdx:
            var = json.loads(json.dumps(base))
            pkg = var["statement"]["predicate"]["packages"][0]
            if "externalRefs" in pkg and pkg["externalRefs"]:
                # Modify first external ref
                ref = pkg["externalRefs"][0]
                if "referenceLocator" in ref:
                    ref["referenceLocator"] = "invalid"  # Invalid value
                    variations.append(("invalid_external_ref_locator", var))
                if "referenceType" in ref:
                    ref["referenceType"] = "invalid"  # Invalid type
                    variations.append(("invalid_external_ref_type", var))
        
        # Try checksum modifications
        if "checksum" in key_str.lower() and is_spdx:
            var = json.loads(json.dumps(base))
            if "pkg." in key_str and "checksums" in var["statement"]["predicate"]["packages"][0]:
                checksums = var["statement"]["predicate"]["packages"][0]["checksums"]
                if checksums:
                    # Modify first checksum
                    checksums[0]["algorithm"] = "INVALID"  # Invalid algorithm
                    variations.append(("invalid_checksum_algorithm", var))
                    # Or duplicate algorithm
                    var2 = json.loads(json.dumps(var))
                    var2["statement"]["predicate"]["packages"][0]["checksums"] = [
                        {"algorithm": "SHA256", "checksumValue": "a" * 64},
                        {"algorithm": "SHA256", "checksumValue": "b" * 64}  # Duplicate
                    ]
                    variations.append(("duplicate_checksum_algorithm", var2))
    
    return variations

def try_extreme_modifications(test_case: Dict, case_id: str) -> Optional[Dict]:
    """Try extreme modifications to trigger a deny."""
    keys_used = test_case.get("keys_used", [])
    is_spdx = "spdx" in case_id.lower() or any("spdx" in str(k).lower() for k in keys_used)
    
    if is_spdx:
        var = create_base_spdx_attestation()
        # Try removing all packages
        var["statement"]["predicate"]["packages"] = []
        return var
    else:
        var = create_base_cyclonedx_attestation()
        var["statement"]["predicate"]["components"] = []
        return var

def main():
    """Generate validation test definitions from requirements (TDD workflow).
    
    For TDD workflow:
    1. Reads requirements.json (natural_language, keys_used, type only)
    2. Generates test data from requirements using pattern matching
    3. Outputs test_case_definitions.json
    4. Note: Execution verification happens AFTER rules are generated
    """
    project_root = Path(__file__).parent.parent.parent
    
    # Try requirements.json first (TDD workflow), fallback to comprehensive_test_cases.json
    requirements_file = project_root / "sbom_data" / "requirements.json"
    comprehensive_file = project_root / "sbom_data" / "comprehensive_test_cases.json"
    output_file = project_root / "sbom_data" / "test_case_definitions.json"
    
    use_requirements = requirements_file.exists()
    
    if use_requirements:
        print("📋 Using TDD workflow: reading from requirements.json")
        with open(requirements_file, 'r') as f:
            data = json.load(f)
        test_cases = data.get("requirements", {})
        source = "requirements.json"
    else:
        print("📋 Using legacy workflow: reading from comprehensive_test_cases.json")
        if not comprehensive_file.exists():
            print(f"Error: Neither {requirements_file} nor {comprehensive_file} exists")
            return
        with open(comprehensive_file, 'r') as f:
            data = json.load(f)
        test_cases = data.get("test_cases", {})
        source = "comprehensive_test_cases.json"
    
    test_definitions = {
        "metadata": {
            "source": source,
            "generated_by": "generate_sbom_validation_tests_execute.py",
            "method": "pattern_matching_from_requirements" if use_requirements else "rego_execution",
            "workflow": "TDD" if use_requirements else "legacy"
        },
        "test_cases": {}
    }
    
    generated = 0
    for case_id, test_case in test_cases.items():
        try:
            # Try to load rego_code from file if not in test_case
            if "rego_code" not in test_case or not test_case.get("rego_code"):
                rule_file = project_root / "sbom_rego_rules" / f"{case_id}.rego"
                if rule_file.exists():
                    test_case["rego_code"] = rule_file.read_text()
            
            # Use execution-based approach if rego_code is available, otherwise use pattern matching
            if test_case.get("rego_code"):
                # Execute rego_code to verify tests (most accurate)
                tests = generate_tests_by_execution(test_case, case_id)
            elif use_requirements:
                # Generate test data from requirements using pattern matching (TDD workflow)
                tests = generate_tests_from_requirements(test_case, case_id)
            else:
                # Legacy: should have rego_code, but fallback to pattern matching
                tests = generate_tests_from_requirements(test_case, case_id)
            
            if tests:
                test_definitions["test_cases"][case_id] = {
                    "natural_language": test_case["natural_language"],
                    "keys_used": test_case.get("keys_used", []),
                    "type": test_case.get("type", "compound"),
                    "tests": tests
                }
                generated += 1
                if generated % 10 == 0:
                    print(f"Generated {generated} test cases...")
        except Exception as e:
            print(f"⚠️  Error generating tests for {case_id}: {e}")
    
    with open(output_file, 'w') as f:
        json.dump(test_definitions, f, indent=2)
    
    print(f"✅ Generated validation tests for {generated} test cases")
    print(f"📁 Output: {output_file}")
    if use_requirements:
        print(f"💡 TDD workflow: Tests generated from requirements only")
        print(f"   Next step: Generate Rego rules to make these tests pass")

if __name__ == "__main__":
    main()
