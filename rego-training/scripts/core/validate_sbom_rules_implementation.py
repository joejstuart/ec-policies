#!/usr/bin/env python3
"""
Validate that SBOM Rego rules actually implement what their natural language says.

This script:
1. Reads comprehensive_test_cases.json
2. For each test case, checks if the Rego code matches the natural language
3. Reports mismatches and issues
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

def analyze_rule_match(natural_language: str, rego_code: str, case_id: str) -> List[str]:
    """Analyze if the Rego rule matches the natural language description."""
    issues = []
    nl_lower = natural_language.lower()
    
    # Pattern 1: "Verify X contains Y" should check count(Y) > 0 or deny when count(Y) == 0
    if "contains" in nl_lower or "has" in nl_lower:
        if "packages" in nl_lower and "spdx" in case_id.lower():
            if "count(sbom.packages) == 0" not in rego_code:
                issues.append("Should check 'count(sbom.packages) == 0' for 'contains packages'")
        elif "components" in nl_lower and "cyclonedx" in case_id.lower():
            if "count(sbom.components) == 0" not in rego_code:
                issues.append("Should check 'count(sbom.components) == 0' for 'contains components'")
        elif "files" in nl_lower:
            if "count(sbom.files) == 0" not in rego_code:
                issues.append("Should check 'count(sbom.files) == 0' for 'contains files'")
    
    # Pattern 2: "Verify all X have Y" should iterate and check each X
    if "all" in nl_lower and ("have" in nl_lower or "has" in nl_lower):
        if "packages" in nl_lower and "spdx" in case_id.lower():
            if "some pkg in sbom.packages" not in rego_code:
                issues.append("Should iterate packages with 'some pkg in sbom.packages'")
        elif "components" in nl_lower and "cyclonedx" in case_id.lower():
            if "some comp in sbom.components" not in rego_code:
                issues.append("Should iterate components with 'some comp in sbom.components'")
        elif "files" in nl_lower:
            if "some file in sbom.files" not in rego_code:
                issues.append("Should iterate files with 'some file in sbom.files'")
    
    # Pattern 3: "Verify no X have Y" should deny when Y exists
    if "no" in nl_lower and ("have" in nl_lower or "has" in nl_lower):
        # This is correct - deny when condition is true
        pass
    
    # Pattern 4: "Verify X has a valid Y" - check if validation logic exists
    if "valid" in nl_lower and "format" in nl_lower:
        if "startswith" not in rego_code and "contains" not in rego_code and "!=" not in rego_code:
            issues.append("Should include format validation (startswith, contains, or !=)")
    
    # Pattern 5: "Verify all X have unique Y" - should check for duplicates
    if "unique" in nl_lower or "duplicate" in nl_lower:
        if "count(" not in rego_code or "!=" not in rego_code:
            issues.append("Should check for duplicates using count comparison")
    
    # Pattern 6: "Verify at least N" - should check count >= N
    if "at least" in nl_lower:
        count_match = re.search(r"at least (\d+)", nl_lower)
        if count_match:
            min_count = count_match.group(1)
            if f"count(" not in rego_code or f"< {min_count}" not in rego_code:
                issues.append(f"Should check 'count(...) < {min_count}' for 'at least {min_count}'")
    
    # Pattern 7: Check if rule uses correct predicateType
    if "spdx" in case_id.lower():
        if 'predicateType == "https://spdx.dev/Document"' not in rego_code:
            issues.append("Should check predicateType for SPDX")
    elif "cyclonedx" in case_id.lower():
        if 'predicateType == "https://cyclonedx.org/bom"' not in rego_code:
            issues.append("Should check predicateType for CycloneDX")
    
    # Pattern 8: Check if rule starts with attestation access
    if not rego_code.strip().startswith("deny contains result if {"):
        issues.append("Rule should start with 'deny contains result if {'")
    
    # Pattern 9: Check for proper attestation iteration
    if "some att in input.attestations" not in rego_code:
        issues.append("Should iterate attestations with 'some att in input.attestations'")
    
    # Pattern 10: Check for "empty" - should check == "" or count == 0
    if "empty" in nl_lower and "non-empty" not in nl_lower:
        if '== ""' not in rego_code and "count(" not in rego_code and "not" not in rego_code:
            issues.append("Should check for empty string or empty array")
    
    # Pattern 11: Check for "non-empty" - should check != "" or count > 0
    if "non-empty" in nl_lower:
        # Check if it's checking for empty (which denies non-empty)
        if '== ""' in rego_code:
            # This is correct - denying when empty means requiring non-empty
            pass
        elif '!= ""' not in rego_code and "count(" not in rego_code and "not" not in rego_code:
            issues.append("Should check for non-empty string or non-empty array")
    
    # Pattern 12: Check for checksum validation
    if "checksum" in nl_lower:
        if "checksums" not in rego_code:
            issues.append("Should access checksums array")
        if "algorithm" in nl_lower or "sha" in nl_lower:
            if "algorithm" not in rego_code:
                issues.append("Should check checksum algorithm")
    
    # Pattern 13: Check for external references
    if "external reference" in nl_lower or "externalref" in nl_lower.lower():
        # SPDX uses externalRefs, CycloneDX uses externalReferences
        if "spdx" in case_id.lower():
            if "externalRefs" not in rego_code:
                issues.append("Should access externalRefs array (SPDX)")
        elif "cyclonedx" in case_id.lower():
            if "externalReferences" not in rego_code:
                issues.append("Should access externalReferences array (CycloneDX)")
    
    # Pattern 14: Check for PURL validation
    if "purl" in nl_lower:
        if "purl" not in rego_code.lower() and "referencelocator" not in rego_code.lower():
            issues.append("Should check PURL in externalRefs")
        if "startswith" in nl_lower or "format" in nl_lower:
            if "startswith" not in rego_code:
                issues.append("Should validate PURL format with startswith")
    
    # Pattern 15: Check for CPE validation
    if "cpe" in nl_lower:
        if "cpe" not in rego_code.lower():
            issues.append("Should check CPE")
    
    # Pattern 16: Check for license validation
    if "license" in nl_lower:
        if "license" not in rego_code.lower():
            issues.append("Should check license field")
    
    # Pattern 17: Check for supplier/originator validation
    if "supplier" in nl_lower:
        if "supplier" not in rego_code.lower():
            issues.append("Should check supplier field")
    if "originator" in nl_lower:
        if "originator" not in rego_code.lower():
            issues.append("Should check originator field")
    
    # Pattern 18: Check for version validation
    if "version" in nl_lower:
        if "version" not in rego_code.lower():
            issues.append("Should check version field")
    
    # Pattern 19: Check for name validation
    if "name" in nl_lower and "package" in nl_lower:
        if "pkg.name" not in rego_code and "comp.name" not in rego_code:
            issues.append("Should check name field")
    
    # Pattern 20: Check for SPDXID validation
    if "spdxid" in nl_lower:
        if "SPDXID" not in rego_code:
            issues.append("Should check SPDXID field")
    
    # Pattern 21: Check for bom-ref validation
    if "bom-ref" in nl_lower or "bomref" in nl_lower:
        if "bom-ref" not in rego_code.lower() and '"bom-ref"' not in rego_code:
            issues.append("Should check bom-ref field")
    
    return issues

def main():
    """Validate all SBOM rules against their natural language."""
    project_root = Path(__file__).parent.parent.parent
    
    comprehensive_file = project_root / "sbom_data" / "comprehensive_test_cases.json"
    
    if not comprehensive_file.exists():
        print(f"❌ Error: {comprehensive_file} does not exist")
        return 1
    
    with open(comprehensive_file) as f:
        data = json.load(f)
    
    test_cases = data.get("test_cases", {})
    print(f"Validating {len(test_cases)} SBOM test cases...\n")
    
    total_issues = 0
    cases_with_issues = []
    
    for case_id, test_case in test_cases.items():
        natural_language = test_case.get("natural_language", "")
        rego_code = test_case.get("rego_code", "")
        
        if not natural_language or not rego_code:
            continue
        
        issues = analyze_rule_match(natural_language, rego_code, case_id)
        
        if issues:
            total_issues += len(issues)
            cases_with_issues.append((case_id, natural_language, issues))
    
    # Report results
    if cases_with_issues:
        print(f"⚠️  Found {total_issues} potential issues across {len(cases_with_issues)} test cases:\n")
        
        for case_id, natural_language, issues in cases_with_issues[:20]:  # Show first 20
            print(f"  {case_id}:")
            print(f"    Description: {natural_language}")
            for issue in issues:
                print(f"    - {issue}")
            print()
        
        if len(cases_with_issues) > 20:
            print(f"  ... and {len(cases_with_issues) - 20} more cases with issues\n")
        
        print(f"Total: {total_issues} issues in {len(cases_with_issues)} cases")
        return 1
    else:
        print(f"✅ All {len(test_cases)} test cases appear to match their natural language descriptions!")
        return 0

if __name__ == "__main__":
    exit(main())
