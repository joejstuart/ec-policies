#!/usr/bin/env python3
"""
Generate comprehensive SBOM test cases covering all fields in SPDX and CycloneDX SBOM structures.

This script generates 200+ test cases covering:
- SPDX document fields
- SPDX package fields
- SPDX file fields
- SPDX external references
- CycloneDX document fields
- CycloneDX component fields
- Complex validation patterns
"""

import json
from typing import Dict, List
from pathlib import Path

def generate_test_case(id: str, natural_language: str, rego_code: str, keys_used: List[str], type: str) -> Dict:
    """Generate a test case entry."""
    return {
        "natural_language": natural_language,
        "rego_code": rego_code,
        "keys_used": keys_used,
        "type": type
    }

def generate_all_sbom_test_cases() -> Dict:
    """Generate all SBOM test cases covering every field."""
    
    test_cases = {}
    case_num = 1
    
    # SPDX Document Level Tests
    spdx_doc_cases = [
        ("sbom_spdx_doc_001", "Verify the SPDX SBOM has a valid SPDXID.", 
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    sbom.SPDXID != \"SPDXRef-DOCUMENT\"\n    result := sprintf(\"SPDX SBOM has invalid SPDXID: %s\", [sbom.SPDXID])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.SPDXID"], "single_key"),
        
        ("sbom_spdx_doc_002", "Verify the SPDX SBOM has a name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not sbom.name\n    result := \"SPDX SBOM has no name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.name"], "single_key"),
        
        ("sbom_spdx_doc_003", "Verify the SPDX SBOM has a valid spdxVersion.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    sbom.spdxVersion != \"SPDX-2.3\"\n    result := sprintf(\"SPDX SBOM has invalid version: %s\", [sbom.spdxVersion])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.spdxVersion"], "single_key"),
        
        ("sbom_spdx_doc_004", "Verify the SPDX SBOM has a documentNamespace.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not sbom.documentNamespace\n    result := \"SPDX SBOM has no documentNamespace\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.documentNamespace"], "single_key"),
        
        ("sbom_spdx_doc_005", "Verify the SPDX SBOM has a dataLicense.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    sbom.dataLicense != \"CC0-1.0\"\n    result := sprintf(\"SPDX SBOM has invalid dataLicense: %s\", [sbom.dataLicense])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.dataLicense"], "single_key"),
        
        ("sbom_spdx_doc_006", "Verify the SPDX SBOM has creation info.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not sbom.creationInfo\n    result := \"SPDX SBOM has no creationInfo\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.creationInfo"], "single_key"),
        
        ("sbom_spdx_doc_007", "Verify the SPDX SBOM has creation info with a created timestamp.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not sbom.creationInfo.created\n    result := \"SPDX SBOM has no creation timestamp\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.creationInfo.created"], "single_key"),
        
        ("sbom_spdx_doc_008", "Verify the SPDX SBOM has at least one creator.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    count(sbom.creationInfo.creators) == 0\n    result := \"SPDX SBOM has no creators\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.creationInfo.creators"], "single_key"),
        
        ("sbom_spdx_doc_009", "Verify the SPDX SBOM contains packages.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    count(sbom.packages) == 0\n    result := \"SPDX SBOM has no packages\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages"], "single_key"),
        
        ("sbom_spdx_doc_010", "Verify the SPDX SBOM contains files.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    count(sbom.files) == 0\n    result := \"SPDX SBOM has no files\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files"], "single_key"),
    ]
    
    # SPDX Package Tests
    spdx_pkg_cases = [
        ("sbom_spdx_pkg_001", "Verify all packages in the SPDX SBOM have a name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not pkg.name\n    result := \"Package in SPDX SBOM has no name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_002", "Verify all packages in the SPDX SBOM have an SPDXID.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not pkg.SPDXID\n    result := sprintf(\"Package %s has no SPDXID\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.SPDXID", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_003", "Verify all packages in the SPDX SBOM have a versionInfo.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not pkg.versionInfo\n    result := sprintf(\"Package %s has no versionInfo\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.versionInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_004", "Verify no packages in the SPDX SBOM have version '(devel)'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.versionInfo == \"(devel)\"\n    result := sprintf(\"Package %s has development version\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.versionInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_005", "Verify all packages in the SPDX SBOM have a downloadLocation.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not pkg.downloadLocation\n    result := sprintf(\"Package %s has no downloadLocation\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.downloadLocation", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_006", "Verify all packages in the SPDX SBOM have a supplier.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.supplier == \"NOASSERTION\"\n    result := sprintf(\"Package %s has no supplier\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.supplier", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_007", "Verify all packages in the SPDX SBOM have an originator.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.originator == \"NOASSERTION\"\n    result := sprintf(\"Package %s has no originator\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.originator", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_008", "Verify all packages in the SPDX SBOM have a licenseDeclared.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.licenseDeclared == \"NOASSERTION\"\n    result := sprintf(\"Package %s has no declared license\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.licenseDeclared", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_009", "Verify all packages in the SPDX SBOM have a licenseConcluded.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.licenseConcluded == \"NOASSERTION\"\n    result := sprintf(\"Package %s has no concluded license\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.licenseConcluded", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_010", "Verify all packages in the SPDX SBOM have a copyrightText.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.copyrightText == \"NOASSERTION\"\n    result := sprintf(\"Package %s has no copyright text\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.copyrightText", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_011", "Verify all packages in the SPDX SBOM have sourceInfo.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not pkg.sourceInfo\n    result := sprintf(\"Package %s has no sourceInfo\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.sourceInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_012", "Verify all packages in the SPDX SBOM have at least one external reference.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    count(pkg.externalRefs) == 0\n    result := sprintf(\"Package %s has no external references\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_013", "Verify all packages in the SPDX SBOM have a PURL external reference.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not any([ref | some ref in pkg.externalRefs; ref.referenceType == \"purl\"])\n    result := sprintf(\"Package %s has no PURL external reference\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_014", "Verify no packages in the SPDX SBOM have external references with type 'cpe23Type'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    ref.referenceType == \"cpe23Type\"\n    result := sprintf(\"Package %s has disallowed CPE reference: %s\", [pkg.name, ref.referenceLocator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_015", "Verify all packages in the SPDX SBOM have external references with category 'PACKAGE_MANAGER'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not any([ref | some ref in pkg.externalRefs; ref.referenceCategory == \"PACKAGE_MANAGER\"])\n    result := sprintf(\"Package %s has no PACKAGE_MANAGER external reference\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceCategory", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_016", "Verify all packages in the SPDX SBOM have checksums.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    count(pkg.checksums) == 0\n    result := sprintf(\"Package %s has no checksums\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_017", "Verify all packages in the SPDX SBOM have a SHA256 checksum.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not any([chk | some chk in pkg.checksums; chk.algorithm == \"SHA256\"])\n    result := sprintf(\"Package %s has no SHA256 checksum\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.algorithm", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_018", "Verify all packages in the SPDX SBOM with filesAnalyzed true have a packageVerificationCode.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.filesAnalyzed == true\n    not pkg.packageVerificationCode\n    result := sprintf(\"Package %s has filesAnalyzed true but no packageVerificationCode\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.filesAnalyzed", "pkg.packageVerificationCode", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_019", "Verify all packages in the SPDX SBOM with packageVerificationCode have a packageVerificationCodeValue.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.packageVerificationCode\n    not pkg.packageVerificationCode.packageVerificationCodeValue\n    result := sprintf(\"Package %s has packageVerificationCode but no value\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.packageVerificationCode", "pkg.packageVerificationCode.packageVerificationCodeValue", "pkg.name"], "compound"),
    ]
    
    # SPDX File Tests
    spdx_file_cases = [
        ("sbom_spdx_file_001", "Verify all files in the SPDX SBOM have a fileName.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    not file.fileName\n    result := \"File in SPDX SBOM has no fileName\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_002", "Verify all files in the SPDX SBOM have an SPDXID.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    not file.SPDXID\n    result := sprintf(\"File %s has no SPDXID\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.SPDXID", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_003", "Verify all files in the SPDX SBOM have checksums.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    count(file.checksums) == 0\n    result := sprintf(\"File %s has no checksums\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_004", "Verify all files in the SPDX SBOM have a SHA256 checksum.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    not any([chk | some chk in file.checksums; chk.algorithm == \"SHA256\"])\n    result := sprintf(\"File %s has no SHA256 checksum\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "chk.algorithm", "file.fileName"], "compound"),
    ]
    
    # CycloneDX Document Tests
    cyclonedx_doc_cases = [
        ("sbom_cyclonedx_doc_001", "Verify the CycloneDX SBOM has a valid bomFormat.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    sbom.bomFormat != \"CycloneDX\"\n    result := sprintf(\"CycloneDX SBOM has invalid bomFormat: %s\", [sbom.bomFormat])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.bomFormat"], "single_key"),
        
        ("sbom_cyclonedx_doc_002", "Verify the CycloneDX SBOM has a specVersion.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.specVersion\n    result := \"CycloneDX SBOM has no specVersion\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.specVersion"], "single_key"),
        
        ("sbom_cyclonedx_doc_003", "Verify the CycloneDX SBOM contains components.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    count(sbom.components) == 0\n    result := \"CycloneDX SBOM has no components\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components"], "single_key"),
        
        ("sbom_cyclonedx_doc_004", "Verify the CycloneDX SBOM has metadata.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.metadata\n    result := \"CycloneDX SBOM has no metadata\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata"], "single_key"),
    ]
    
    # CycloneDX Component Tests
    cyclonedx_comp_cases = [
        ("sbom_cyclonedx_comp_001", "Verify all components in the CycloneDX SBOM have a name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    not comp.name\n    result := \"Component in CycloneDX SBOM has no name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_002", "Verify all components in the CycloneDX SBOM have a type.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    not comp.type\n    result := sprintf(\"Component %s has no type\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.type", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_003", "Verify all components in the CycloneDX SBOM are of type 'library'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.type != \"library\"\n    result := sprintf(\"Component %s has type %s, expected library\", [comp.name, comp.type])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.type", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_004", "Verify all components in the CycloneDX SBOM have a version.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    not comp.version\n    result := sprintf(\"Component %s has no version\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.version", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_005", "Verify all components in the CycloneDX SBOM have a purl.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    not comp.purl\n    result := sprintf(\"Component %s has no purl\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.purl", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_006", "Verify all components in the CycloneDX SBOM have a bom-ref.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    not comp[\"bom-ref\"]\n    result := sprintf(\"Component %s has no bom-ref\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.bom-ref", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_007", "Verify all components in the CycloneDX SBOM have licenses.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    count(comp.licenses) == 0\n    result := sprintf(\"Component %s has no licenses\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.licenses", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_008", "Verify all components in the CycloneDX SBOM have a publisher.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    not comp.publisher\n    result := sprintf(\"Component %s has no publisher\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.publisher", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_009", "Verify all components in the CycloneDX SBOM have a cpe.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    not comp.cpe\n    result := sprintf(\"Component %s has no cpe\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.cpe", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_010", "Verify all components in the CycloneDX SBOM have properties.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    count(comp.properties) == 0\n    result := sprintf(\"Component %s has no properties\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.properties", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_011", "Verify all components in the CycloneDX SBOM have externalReferences.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    count(comp.externalReferences) == 0\n    result := sprintf(\"Component %s has no externalReferences\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.externalReferences", "comp.name"], "compound"),
    ]
    
    # Additional Complex Patterns
    complex_patterns = [
        ("sbom_spdx_complex_001", "Verify no packages in the SPDX SBOM have external references with referenceCategory 'SECURITY'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    ref.referenceCategory == \"SECURITY\"\n    result := sprintf(\"Package %s has SECURITY external reference: %s\", [pkg.name, ref.referenceLocator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceCategory", "ref.referenceLocator", "pkg.name"], "compound"),
        
        ("sbom_spdx_complex_002", "Verify all packages in the SPDX SBOM with filesAnalyzed true have at least one file.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.filesAnalyzed == true\n    count(sbom.files) == 0\n    result := sprintf(\"Package %s has filesAnalyzed true but SBOM has no files\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.filesAnalyzed", "statement.predicate.files", "pkg.name"], "compound"),
        
        ("sbom_spdx_complex_003", "Verify the SPDX SBOM name contains '@sha256:'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not contains(sbom.name, \"@sha256:\")\n    result := sprintf(\"SPDX SBOM name %s does not contain @sha256:\", [sbom.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.name"], "single_key"),
        
        ("sbom_spdx_complex_004", "Verify the SPDX SBOM documentNamespace contains 'spdxdocs'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not contains(sbom.documentNamespace, \"spdxdocs\")\n    result := sprintf(\"SPDX SBOM documentNamespace %s does not contain spdxdocs\", [sbom.documentNamespace])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.documentNamespace"], "single_key"),
        
        ("sbom_cyclonedx_complex_001", "Verify the CycloneDX SBOM metadata has a timestamp.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.metadata.timestamp\n    result := \"CycloneDX SBOM metadata has no timestamp\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.timestamp"], "single_key"),
        
        ("sbom_cyclonedx_complex_002", "Verify the CycloneDX SBOM metadata has tools.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    count(sbom.metadata.tools) == 0\n    result := \"CycloneDX SBOM metadata has no tools\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools"], "single_key"),
        
        ("sbom_cyclonedx_complex_003", "Verify all tools in the CycloneDX SBOM metadata have a name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some tool in sbom.metadata.tools\n    not tool.name\n    result := \"Tool in CycloneDX SBOM metadata has no name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools", "tool.name"], "compound"),
        
        ("sbom_cyclonedx_complex_004", "Verify all tools in the CycloneDX SBOM metadata have a version.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some tool in sbom.metadata.tools\n    not tool.version\n    result := sprintf(\"Tool %s in CycloneDX SBOM metadata has no version\", [tool.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools", "tool.version", "tool.name"], "compound"),
    ]
    
    # Additional SPDX Package Field Variations
    spdx_pkg_variations = [
        ("sbom_spdx_pkg_020", "Verify all packages in the SPDX SBOM have a valid SPDXID format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not startswith(pkg.SPDXID, \"SPDXRef-\")\n    result := sprintf(\"Package %s has invalid SPDXID format: %s\", [pkg.name, pkg.SPDXID])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.SPDXID", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_021", "Verify all packages in the SPDX SBOM have external references with valid referenceLocator.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    not ref.referenceLocator\n    result := sprintf(\"Package %s has external reference with no referenceLocator\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceLocator", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_022", "Verify all packages in the SPDX SBOM have external references with valid referenceType.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    not ref.referenceType\n    result := sprintf(\"Package %s has external reference with no referenceType\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_023", "Verify all packages in the SPDX SBOM have external references with valid referenceCategory.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    not ref.referenceCategory\n    result := sprintf(\"Package %s has external reference with no referenceCategory\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceCategory", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_024", "Verify all packages in the SPDX SBOM have checksums with valid algorithm.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some chk in pkg.checksums\n    not chk.algorithm\n    result := sprintf(\"Package %s has checksum with no algorithm\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.algorithm", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_025", "Verify all packages in the SPDX SBOM have checksums with valid checksumValue.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some chk in pkg.checksums\n    not chk.checksumValue\n    result := sprintf(\"Package %s has checksum with no checksumValue\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.checksumValue", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_026", "Verify all packages in the SPDX SBOM have a SHA1 checksum.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    not any([chk | some chk in pkg.checksums; chk.algorithm == \"SHA1\"])\n    result := sprintf(\"Package %s has no SHA1 checksum\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.algorithm", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_027", "Verify all packages in the SPDX SBOM have a valid downloadLocation format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.downloadLocation != \"NOASSERTION\"\n    not startswith(pkg.downloadLocation, \"http\")\n    not startswith(pkg.downloadLocation, \"git+\")\n    result := sprintf(\"Package %s has invalid downloadLocation format: %s\", [pkg.name, pkg.downloadLocation])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.downloadLocation", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_028", "Verify all packages in the SPDX SBOM have a valid supplier format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.supplier != \"NOASSERTION\"\n    not contains(pkg.supplier, \":\")\n    result := sprintf(\"Package %s has invalid supplier format: %s\", [pkg.name, pkg.supplier])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.supplier", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_029", "Verify all packages in the SPDX SBOM have a valid originator format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.originator != \"NOASSERTION\"\n    not contains(pkg.originator, \":\")\n    result := sprintf(\"Package %s has invalid originator format: %s\", [pkg.name, pkg.originator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.originator", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_030", "Verify no packages in the SPDX SBOM have empty versionInfo.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.versionInfo == \"\"\n    result := sprintf(\"Package %s has empty versionInfo\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.versionInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_031", "Verify all packages in the SPDX SBOM have a valid licenseDeclared format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.licenseDeclared != \"NOASSERTION\"\n    not contains(pkg.licenseDeclared, \"-\")\n    not startswith(pkg.licenseDeclared, \"LicenseRef-\")\n    result := sprintf(\"Package %s has invalid licenseDeclared format: %s\", [pkg.name, pkg.licenseDeclared])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.licenseDeclared", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_032", "Verify all packages in the SPDX SBOM have a valid licenseConcluded format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.licenseConcluded != \"NOASSERTION\"\n    not contains(pkg.licenseConcluded, \"-\")\n    not startswith(pkg.licenseConcluded, \"LicenseRef-\")\n    result := sprintf(\"Package %s has invalid licenseConcluded format: %s\", [pkg.name, pkg.licenseConcluded])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.licenseConcluded", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_033", "Verify all packages in the SPDX SBOM have PURL external references starting with 'pkg:'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    ref.referenceType == \"purl\"\n    not startswith(ref.referenceLocator, \"pkg:\")\n    result := sprintf(\"Package %s has invalid PURL format: %s\", [pkg.name, ref.referenceLocator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_034", "Verify all packages in the SPDX SBOM have CPE external references starting with 'cpe:'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    ref.referenceType == \"cpe23Type\"\n    not startswith(ref.referenceLocator, \"cpe:\")\n    result := sprintf(\"Package %s has invalid CPE format: %s\", [pkg.name, ref.referenceLocator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator", "pkg.name"], "compound"),
    ]
    
    # Additional SPDX File Variations
    spdx_file_variations = [
        ("sbom_spdx_file_005", "Verify all files in the SPDX SBOM have a valid SPDXID format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    not startswith(file.SPDXID, \"SPDXRef-\")\n    result := sprintf(\"File %s has invalid SPDXID format: %s\", [file.fileName, file.SPDXID])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.SPDXID", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_006", "Verify all files in the SPDX SBOM have checksums with valid algorithm.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    some chk in file.checksums\n    not chk.algorithm\n    result := sprintf(\"File %s has checksum with no algorithm\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "chk.algorithm", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_007", "Verify all files in the SPDX SBOM have checksums with valid checksumValue.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    some chk in file.checksums\n    not chk.checksumValue\n    result := sprintf(\"File %s has checksum with no checksumValue\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "chk.checksumValue", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_008", "Verify all files in the SPDX SBOM have a SHA1 checksum.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    not any([chk | some chk in file.checksums; chk.algorithm == \"SHA1\"])\n    result := sprintf(\"File %s has no SHA1 checksum\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "chk.algorithm", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_009", "Verify all files in the SPDX SBOM have fileName starting with '/'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    not startswith(file.fileName, \"/\")\n    result := sprintf(\"File %s does not start with /\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.fileName"], "compound"),
    ]
    
    # Additional SPDX Document Variations
    spdx_doc_variations = [
        ("sbom_spdx_doc_011", "Verify the SPDX SBOM documentNamespace is a valid URL.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not startswith(sbom.documentNamespace, \"http\")\n    result := sprintf(\"SPDX SBOM documentNamespace is not a valid URL: %s\", [sbom.documentNamespace])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.documentNamespace"], "single_key"),
        
        ("sbom_spdx_doc_012", "Verify the SPDX SBOM creationInfo has a valid licenseListVersion.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not sbom.creationInfo.licenseListVersion\n    result := \"SPDX SBOM creationInfo has no licenseListVersion\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.creationInfo.licenseListVersion"], "single_key"),
        
        ("sbom_spdx_doc_013", "Verify all creators in the SPDX SBOM have a valid format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some creator in sbom.creationInfo.creators\n    not contains(creator, \":\")\n    result := sprintf(\"SPDX SBOM has invalid creator format: %s\", [creator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.creationInfo.creators"], "single_key"),
        
        ("sbom_spdx_doc_014", "Verify the SPDX SBOM creationInfo created timestamp is valid ISO 8601.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not contains(sbom.creationInfo.created, \"T\")\n    result := sprintf(\"SPDX SBOM creation timestamp is not valid ISO 8601: %s\", [sbom.creationInfo.created])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.creationInfo.created"], "single_key"),
    ]
    
    # Additional CycloneDX Component Variations
    cyclonedx_comp_variations = [
        ("sbom_cyclonedx_comp_012", "Verify all components in the CycloneDX SBOM have a valid purl format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.purl\n    not startswith(comp.purl, \"pkg:\")\n    result := sprintf(\"Component %s has invalid purl format: %s\", [comp.name, comp.purl])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.purl", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_013", "Verify all components in the CycloneDX SBOM have a valid cpe format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.cpe\n    not startswith(comp.cpe, \"cpe:\")\n    result := sprintf(\"Component %s has invalid cpe format: %s\", [comp.name, comp.cpe])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.cpe", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_014", "Verify all components in the CycloneDX SBOM have licenses with valid structure.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    some license_entry in comp.licenses\n    not license_entry.license\n    result := sprintf(\"Component %s has license entry with no license object\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.licenses", "license_entry.license", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_015", "Verify all components in the CycloneDX SBOM have licenses with a name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    some license_entry in comp.licenses\n    license_entry.license\n    not license_entry.license.name\n    result := sprintf(\"Component %s has license with no name\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.licenses", "license_entry.license.name", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_016", "Verify all components in the CycloneDX SBOM have properties with a name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    some prop in comp.properties\n    not prop.name\n    result := sprintf(\"Component %s has property with no name\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.properties", "prop.name", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_017", "Verify all components in the CycloneDX SBOM have externalReferences with a type.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    some ext_ref in comp.externalReferences\n    not ext_ref.type\n    result := sprintf(\"Component %s has externalReference with no type\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.externalReferences", "ext_ref.type", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_018", "Verify all components in the CycloneDX SBOM have externalReferences with a url.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    some ext_ref in comp.externalReferences\n    not ext_ref.url\n    result := sprintf(\"Component %s has externalReference with no url\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.externalReferences", "ext_ref.url", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_019", "Verify all components in the CycloneDX SBOM have externalReferences with valid url format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    some ext_ref in comp.externalReferences\n    ext_ref.url\n    not startswith(ext_ref.url, \"http\")\n    result := sprintf(\"Component %s has externalReference with invalid url format: %s\", [comp.name, ext_ref.url])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.externalReferences", "ext_ref.url", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_020", "Verify no components in the CycloneDX SBOM have empty version.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.version == \"\"\n    result := sprintf(\"Component %s has empty version\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.version", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_021", "Verify all components in the CycloneDX SBOM have valid type values.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.type not in [\"application\", \"library\", \"container\", \"file\", \"firmware\", \"operating-system\"]\n    result := sprintf(\"Component %s has invalid type: %s\", [comp.name, comp.type])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.type", "comp.name"], "compound"),
    ]
    
    # Additional CycloneDX Document Variations
    cyclonedx_doc_variations = [
        ("sbom_cyclonedx_doc_005", "Verify the CycloneDX SBOM has a valid specVersion format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not contains(sbom.specVersion, \".\")\n    result := sprintf(\"CycloneDX SBOM has invalid specVersion format: %s\", [sbom.specVersion])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.specVersion"], "single_key"),
        
        ("sbom_cyclonedx_doc_006", "Verify the CycloneDX SBOM metadata has a component.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.metadata.component\n    result := \"CycloneDX SBOM metadata has no component\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.component"], "single_key"),
        
        ("sbom_cyclonedx_doc_007", "Verify the CycloneDX SBOM metadata component has a name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.metadata.component.name\n    result := \"CycloneDX SBOM metadata component has no name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.component.name"], "single_key"),
        
        ("sbom_cyclonedx_doc_008", "Verify the CycloneDX SBOM metadata component has a type.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.metadata.component.type\n    result := \"CycloneDX SBOM metadata component has no type\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.component.type"], "single_key"),
        
        ("sbom_cyclonedx_doc_009", "Verify the CycloneDX SBOM metadata timestamp is valid ISO 8601.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    sbom.metadata.timestamp\n    not contains(sbom.metadata.timestamp, \"T\")\n    result := sprintf(\"CycloneDX SBOM metadata timestamp is not valid ISO 8601: %s\", [sbom.metadata.timestamp])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.timestamp"], "single_key"),
        
        ("sbom_cyclonedx_doc_010", "Verify all tools in the CycloneDX SBOM metadata have a vendor.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some tool in sbom.metadata.tools\n    not tool.vendor\n    result := sprintf(\"Tool %s in CycloneDX SBOM metadata has no vendor\", [tool.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools", "tool.vendor", "tool.name"], "compound"),
    ]
    
    # More Complex Patterns
    more_complex_patterns = [
        ("sbom_spdx_complex_005", "Verify the SPDX SBOM has at least one package with a PURL containing 'rpm'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    pkg_purls := {ref.referenceLocator | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceType == \"purl\"}\n    not any([contains(purl, \"rpm\") | some purl in pkg_purls])\n    result := \"SPDX SBOM has no package with RPM PURL\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator"], "compound"),
        
        ("sbom_spdx_complex_006", "Verify the SPDX SBOM has at least one package with a PURL containing 'golang'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    pkg_purls := {ref.referenceLocator | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceType == \"purl\"}\n    not any([contains(purl, \"golang\") | some purl in pkg_purls])\n    result := \"SPDX SBOM has no package with Golang PURL\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator"], "compound"),
        
        ("sbom_spdx_complex_007", "Verify all packages in the SPDX SBOM with versionInfo starting with 'v' have valid version format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    startswith(pkg.versionInfo, \"v\")\n    version_num := trim_prefix(pkg.versionInfo, \"v\")\n    not contains(version_num, \".\")\n    result := sprintf(\"Package %s has invalid version format: %s\", [pkg.name, pkg.versionInfo])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.versionInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_complex_008", "Verify the SPDX SBOM has packages from at least one package manager type.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    pkg_managers := {ref.referenceLocator | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceCategory == \"PACKAGE_MANAGER\"}\n    count(pkg_managers) == 0\n    result := \"SPDX SBOM has no packages from package managers\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceCategory"], "compound"),
        
        ("sbom_cyclonedx_complex_005", "Verify the CycloneDX SBOM has components with at least one purl type.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    purl_types := {split(comp.purl, \"/\")[1] | some comp in sbom.components; comp.purl}\n    count(purl_types) == 0\n    result := \"CycloneDX SBOM has no components with purl types\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.purl"], "compound"),
        
        ("sbom_cyclonedx_complex_006", "Verify all components in the CycloneDX SBOM with purl have valid purl type.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.purl\n    purl_parts := split(comp.purl, \"/\")\n    count(purl_parts) < 2\n    result := sprintf(\"Component %s has invalid purl structure: %s\", [comp.name, comp.purl])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.purl", "comp.name"], "compound"),
    ]
    
    # Even More SPDX Package Patterns
    spdx_pkg_more = [
        ("sbom_spdx_pkg_035", "Verify all packages in the SPDX SBOM have unique SPDXIDs.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    pkg_ids := {pkg.SPDXID | some pkg in sbom.packages}\n    count(pkg_ids) != count(sbom.packages)\n    result := \"SPDX SBOM has duplicate package SPDXIDs\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.SPDXID"], "compound"),
        
        ("sbom_spdx_pkg_036", "Verify all packages in the SPDX SBOM have unique names.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    pkg_names := {pkg.name | some pkg in sbom.packages}\n    count(pkg_names) != count(sbom.packages)\n    result := \"SPDX SBOM has duplicate package names\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_037", "Verify all packages in the SPDX SBOM have at least one checksum algorithm in ['SHA1', 'SHA256', 'MD5'].",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    valid_algorithms := {chk.algorithm | some chk in pkg.checksums; chk.algorithm in [\"SHA1\", \"SHA256\", \"MD5\"]}\n    count(valid_algorithms) == 0\n    result := sprintf(\"Package %s has no valid checksum algorithm\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.algorithm", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_038", "Verify all packages in the SPDX SBOM have external references with unique referenceLocators.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    ref_locators := {ref.referenceLocator | some ref in pkg.externalRefs}\n    count(ref_locators) != count(pkg.externalRefs)\n    result := sprintf(\"Package %s has duplicate external reference locators\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceLocator", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_039", "Verify all packages in the SPDX SBOM have checksums with unique algorithms.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    chk_algorithms := {chk.algorithm | some chk in pkg.checksums}\n    count(chk_algorithms) != count(pkg.checksums)\n    result := sprintf(\"Package %s has duplicate checksum algorithms\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.algorithm", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_040", "Verify all packages in the SPDX SBOM with packageVerificationCode have a non-empty value.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.packageVerificationCode\n    pkg.packageVerificationCode.packageVerificationCodeValue == \"\"\n    result := sprintf(\"Package %s has empty packageVerificationCode value\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.packageVerificationCode", "pkg.packageVerificationCode.packageVerificationCodeValue", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_041", "Verify all packages in the SPDX SBOM have sourceInfo containing 'acquired'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.sourceInfo\n    not contains(pkg.sourceInfo, \"acquired\")\n    result := sprintf(\"Package %s sourceInfo does not contain 'acquired': %s\", [pkg.name, pkg.sourceInfo])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.sourceInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_042", "Verify all packages in the SPDX SBOM have a non-empty name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.name == \"\"\n    result := \"Package in SPDX SBOM has empty name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_043", "Verify all packages in the SPDX SBOM have a non-empty SPDXID.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.SPDXID == \"\"\n    result := sprintf(\"Package %s has empty SPDXID\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.SPDXID", "pkg.name"], "compound"),
        
        ("sbom_spdx_pkg_044", "Verify all packages in the SPDX SBOM have external references with referenceType in allowed types.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    ref.referenceType not in [\"purl\", \"cpe23Type\", \"swid\", \"maven-central\", \"npm\", \"nuget\", \"pypi\", \"gem\", \"other\"]\n    result := sprintf(\"Package %s has disallowed referenceType: %s\", [pkg.name, ref.referenceType])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "pkg.name"], "compound"),
    ]
    
    # More SPDX File Patterns
    spdx_file_more = [
        ("sbom_spdx_file_010", "Verify all files in the SPDX SBOM have unique SPDXIDs.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    file_ids := {file.SPDXID | some file in sbom.files}\n    count(file_ids) != count(sbom.files)\n    result := \"SPDX SBOM has duplicate file SPDXIDs\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.SPDXID"], "compound"),
        
        ("sbom_spdx_file_011", "Verify all files in the SPDX SBOM have unique fileNames.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    file_names := {file.fileName | some file in sbom.files}\n    count(file_names) != count(sbom.files)\n    result := \"SPDX SBOM has duplicate file names\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_012", "Verify all files in the SPDX SBOM have checksums with unique algorithms.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    chk_algorithms := {chk.algorithm | some chk in file.checksums}\n    count(chk_algorithms) != count(file.checksums)\n    result := sprintf(\"File %s has duplicate checksum algorithms\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "chk.algorithm", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_013", "Verify all files in the SPDX SBOM have a non-empty fileName.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    file.fileName == \"\"\n    result := \"File in SPDX SBOM has empty fileName\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.fileName"], "compound"),
        
        ("sbom_spdx_file_014", "Verify all files in the SPDX SBOM have a non-empty SPDXID.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    file.SPDXID == \"\"\n    result := sprintf(\"File %s has empty SPDXID\", [file.fileName])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.SPDXID", "file.fileName"], "compound"),
    ]
    
    # More CycloneDX Component Patterns
    cyclonedx_comp_more = [
        ("sbom_cyclonedx_comp_022", "Verify all components in the CycloneDX SBOM have unique bom-refs.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    bom_refs := {comp[\"bom-ref\"] | some comp in sbom.components}\n    count(bom_refs) != count(sbom.components)\n    result := \"CycloneDX SBOM has duplicate bom-refs\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.bom-ref"], "compound"),
        
        ("sbom_cyclonedx_comp_023", "Verify all components in the CycloneDX SBOM have unique names.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    comp_names := {comp.name | some comp in sbom.components}\n    count(comp_names) != count(sbom.components)\n    result := \"CycloneDX SBOM has duplicate component names\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_024", "Verify all components in the CycloneDX SBOM have unique purls.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    comp_purls := {comp.purl | some comp in sbom.components; comp.purl}\n    purl_count := count([comp | some comp in sbom.components; comp.purl])\n    count(comp_purls) != purl_count\n    result := \"CycloneDX SBOM has duplicate component purls\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.purl"], "compound"),
        
        ("sbom_cyclonedx_comp_025", "Verify all components in the CycloneDX SBOM have a non-empty name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.name == \"\"\n    result := \"Component in CycloneDX SBOM has empty name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_026", "Verify all components in the CycloneDX SBOM have a non-empty bom-ref.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp[\"bom-ref\"] == \"\"\n    result := sprintf(\"Component %s has empty bom-ref\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.bom-ref", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_027", "Verify all components in the CycloneDX SBOM have properties with unique names.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    prop_names := {prop.name | some prop in comp.properties}\n    count(prop_names) != count(comp.properties)\n    result := sprintf(\"Component %s has duplicate property names\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.properties", "prop.name", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_028", "Verify all components in the CycloneDX SBOM have externalReferences with unique types.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    ext_ref_types := {ext_ref.type | some ext_ref in comp.externalReferences}\n    count(ext_ref_types) != count(comp.externalReferences)\n    result := sprintf(\"Component %s has duplicate externalReference types\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.externalReferences", "ext_ref.type", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_comp_029", "Verify all components in the CycloneDX SBOM have licenses with unique names.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    license_names := {lic.license.name | some lic in comp.licenses; lic.license.name}\n    license_count := count([lic | some lic in comp.licenses; lic.license.name])\n    count(license_names) != license_count\n    result := sprintf(\"Component %s has duplicate license names\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.licenses", "license_entry.license.name", "comp.name"], "compound"),
    ]
    
    # Additional Edge Cases and Validations
    edge_cases = [
        ("sbom_spdx_edge_001", "Verify the SPDX SBOM has at least one attestation with predicateType 'https://spdx.dev/Document'.",
         "deny contains result if {\n    spdx_count := count([att | some att in input.attestations; att.statement.predicateType == \"https://spdx.dev/Document\"])\n    spdx_count == 0\n    result := \"No SPDX SBOM attestations found\"\n}",
         ["input.attestations", "statement.predicateType"], "single_key"),
        
        ("sbom_cyclonedx_edge_001", "Verify the CycloneDX SBOM has at least one attestation with predicateType 'https://cyclonedx.org/bom'.",
         "deny contains result if {\n    cyclonedx_count := count([att | some att in input.attestations; att.statement.predicateType == \"https://cyclonedx.org/bom\"])\n    cyclonedx_count == 0\n    result := \"No CycloneDX SBOM attestations found\"\n}",
         ["input.attestations", "statement.predicateType"], "single_key"),
        
        ("sbom_spdx_edge_002", "Verify all SPDX SBOMs have unique names.",
         "deny contains result if {\n    sbom_names := {sbom.name | some att in input.attestations; statement := att.statement; statement.predicateType == \"https://spdx.dev/Document\"; sbom := statement.predicate}\n    sbom_count := count([att | some att in input.attestations; att.statement.predicateType == \"https://spdx.dev/Document\"])\n    count(sbom_names) != sbom_count\n    result := \"SPDX SBOMs have duplicate names\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.name"], "compound"),
        
        ("sbom_cyclonedx_edge_002", "Verify all CycloneDX SBOMs have unique serialNumbers.",
         "deny contains result if {\n    serial_numbers := {sbom.serialNumber | some att in input.attestations; statement := att.statement; statement.predicateType == \"https://cyclonedx.org/bom\"; sbom := statement.predicate; sbom.serialNumber}\n    sbom_count := count([att | some att in input.attestations; att.statement.predicateType == \"https://cyclonedx.org/bom\"])\n    count(serial_numbers) != sbom_count\n    result := \"CycloneDX SBOMs have duplicate serialNumbers\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.serialNumber"], "compound"),
    ]
    
    # Additional Pattern Matching and Validation Cases
    pattern_matching = [
        ("sbom_spdx_pattern_001", "Verify all packages in the SPDX SBOM have PURLs containing '@'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    ref.referenceType == \"purl\"\n    not contains(ref.referenceLocator, \"@\")\n    result := sprintf(\"Package %s has PURL without @: %s\", [pkg.name, ref.referenceLocator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator", "pkg.name"], "compound"),
        
        ("sbom_spdx_pattern_002", "Verify all packages in the SPDX SBOM have versionInfo not starting with 'v' when it contains numbers.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    contains(pkg.versionInfo, \"0\")\n    contains(pkg.versionInfo, \"1\")\n    contains(pkg.versionInfo, \"2\")\n    contains(pkg.versionInfo, \"3\")\n    contains(pkg.versionInfo, \"4\")\n    contains(pkg.versionInfo, \"5\")\n    contains(pkg.versionInfo, \"6\")\n    contains(pkg.versionInfo, \"7\")\n    contains(pkg.versionInfo, \"8\")\n    contains(pkg.versionInfo, \"9\")\n    startswith(pkg.versionInfo, \"v\")\n    result := sprintf(\"Package %s has versionInfo starting with 'v': %s\", [pkg.name, pkg.versionInfo])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.versionInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_pattern_003", "Verify the SPDX SBOM name matches expected image reference pattern.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    not contains(sbom.name, \"@\")\n    result := sprintf(\"SPDX SBOM name does not match image reference pattern: %s\", [sbom.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.name"], "single_key"),
        
        ("sbom_spdx_pattern_004", "Verify all packages in the SPDX SBOM have supplier starting with 'Organization:' or 'Person:'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.supplier != \"NOASSERTION\"\n    not startswith(pkg.supplier, \"Organization:\")\n    not startswith(pkg.supplier, \"Person:\")\n    result := sprintf(\"Package %s has invalid supplier format: %s\", [pkg.name, pkg.supplier])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.supplier", "pkg.name"], "compound"),
        
        ("sbom_spdx_pattern_005", "Verify all packages in the SPDX SBOM have originator starting with 'Organization:' or 'Person:'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.originator != \"NOASSERTION\"\n    not startswith(pkg.originator, \"Organization:\")\n    not startswith(pkg.originator, \"Person:\")\n    result := sprintf(\"Package %s has invalid originator format: %s\", [pkg.name, pkg.originator])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.originator", "pkg.name"], "compound"),
        
        ("sbom_cyclonedx_pattern_001", "Verify all components in the CycloneDX SBOM have purl containing '@' when version exists.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.purl\n    comp.version\n    not contains(comp.purl, \"@\")\n    result := sprintf(\"Component %s has purl without @ despite having version: %s\", [comp.name, comp.purl])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.purl", "comp.version", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_pattern_002", "Verify all components in the CycloneDX SBOM have cpe containing 'cpe:2.3:'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.cpe\n    not contains(comp.cpe, \"cpe:2.3:\")\n    result := sprintf(\"Component %s has invalid cpe format: %s\", [comp.name, comp.cpe])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.cpe", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_pattern_003", "Verify all tools in the CycloneDX SBOM metadata have name containing at least one letter.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some tool in sbom.metadata.tools\n    not regex.match(\"[a-zA-Z]\", tool.name)\n    result := sprintf(\"Tool %s has name without letters\", [tool.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools", "tool.name"], "compound"),
    ]
    
    # Additional Count and Array Validations
    count_validations = [
        ("sbom_spdx_count_001", "Verify the SPDX SBOM has at least 10 packages.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    count(sbom.packages) < 10\n    result := sprintf(\"SPDX SBOM has only %d packages, expected at least 10\", [count(sbom.packages)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages"], "single_key"),
        
        ("sbom_spdx_count_002", "Verify the SPDX SBOM has at least 5 files.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    count(sbom.files) < 5\n    result := sprintf(\"SPDX SBOM has only %d files, expected at least 5\", [count(sbom.files)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files"], "single_key"),
        
        ("sbom_spdx_count_003", "Verify all packages in the SPDX SBOM have at least 2 external references.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    count(pkg.externalRefs) < 2\n    result := sprintf(\"Package %s has only %d external references, expected at least 2\", [pkg.name, count(pkg.externalRefs)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "pkg.name"], "compound"),
        
        ("sbom_spdx_count_004", "Verify all packages in the SPDX SBOM have at least 2 checksums.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    count(pkg.checksums) < 2\n    result := sprintf(\"Package %s has only %d checksums, expected at least 2\", [pkg.name, count(pkg.checksums)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "pkg.name"], "compound"),
        
        ("sbom_spdx_count_005", "Verify all files in the SPDX SBOM have at least 2 checksums.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    count(file.checksums) < 2\n    result := sprintf(\"File %s has only %d checksums, expected at least 2\", [file.fileName, count(file.checksums)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "file.fileName"], "compound"),
        
        ("sbom_cyclonedx_count_001", "Verify the CycloneDX SBOM has at least 10 components.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    count(sbom.components) < 10\n    result := sprintf(\"CycloneDX SBOM has only %d components, expected at least 10\", [count(sbom.components)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components"], "single_key"),
        
        ("sbom_cyclonedx_count_002", "Verify all components in the CycloneDX SBOM have at least one license.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    count(comp.licenses) < 1\n    result := sprintf(\"Component %s has no licenses\", [comp.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.licenses", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_count_003", "Verify the CycloneDX SBOM metadata has at least one tool.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    count(sbom.metadata.tools) < 1\n    result := \"CycloneDX SBOM metadata has no tools\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools"], "single_key"),
    ]
    
    # SPDX Annotations and Relationships
    spdx_advanced = [
        ("sbom_spdx_adv_001", "Verify all packages in the SPDX SBOM with annotations have valid annotation format.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some annotation in pkg.annotations\n    not annotation.annotator\n    result := sprintf(\"Package %s has annotation with no annotator\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.annotations", "annotation.annotator", "pkg.name"], "compound"),
        
        ("sbom_spdx_adv_002", "Verify all packages in the SPDX SBOM with annotations have annotationDate.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some annotation in pkg.annotations\n    not annotation.annotationDate\n    result := sprintf(\"Package %s has annotation with no annotationDate\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.annotations", "annotation.annotationDate", "pkg.name"], "compound"),
        
        ("sbom_spdx_adv_003", "Verify all packages in the SPDX SBOM with annotations have annotationType.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some annotation in pkg.annotations\n    not annotation.annotationType\n    result := sprintf(\"Package %s has annotation with no annotationType\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.annotations", "annotation.annotationType", "pkg.name"], "compound"),
        
        ("sbom_spdx_adv_004", "Verify the SPDX SBOM has relationships.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    count(sbom.relationships) == 0\n    result := \"SPDX SBOM has no relationships\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.relationships"], "single_key"),
        
        ("sbom_spdx_adv_005", "Verify all relationships in the SPDX SBOM have spdxElementId.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some rel in sbom.relationships\n    not rel.spdxElementId\n    result := \"Relationship in SPDX SBOM has no spdxElementId\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.relationships", "rel.spdxElementId"], "compound"),
        
        ("sbom_spdx_adv_006", "Verify all relationships in the SPDX SBOM have relatedSpdxElement.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some rel in sbom.relationships\n    not rel.relatedSpdxElement\n    result := \"Relationship in SPDX SBOM has no relatedSpdxElement\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.relationships", "rel.relatedSpdxElement"], "compound"),
        
        ("sbom_spdx_adv_007", "Verify all relationships in the SPDX SBOM have relationshipType.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some rel in sbom.relationships\n    not rel.relationshipType\n    result := \"Relationship in SPDX SBOM has no relationshipType\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.relationships", "rel.relationshipType"], "compound"),
    ]
    
    # Additional Field Presence Checks
    field_presence = [
        ("sbom_spdx_field_001", "Verify the SPDX SBOM has dataLicense set to 'CC0-1.0'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    sbom.dataLicense != \"CC0-1.0\"\n    result := sprintf(\"SPDX SBOM has incorrect dataLicense: %s\", [sbom.dataLicense])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.dataLicense"], "single_key"),
        
        ("sbom_spdx_field_002", "Verify all packages in the SPDX SBOM have filesAnalyzed set to boolean.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.filesAnalyzed != true\n    pkg.filesAnalyzed != false\n    result := sprintf(\"Package %s has invalid filesAnalyzed value\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.filesAnalyzed", "pkg.name"], "compound"),
        
        ("sbom_spdx_field_003", "Verify the SPDX SBOM creationInfo has licenseListVersion in format 'X.Y'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    sbom.creationInfo.licenseListVersion\n    not contains(sbom.creationInfo.licenseListVersion, \".\")\n    result := sprintf(\"SPDX SBOM licenseListVersion has invalid format: %s\", [sbom.creationInfo.licenseListVersion])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.creationInfo.licenseListVersion"], "single_key"),
        
        ("sbom_cyclonedx_field_001", "Verify the CycloneDX SBOM has a version field.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.version\n    result := \"CycloneDX SBOM has no version field\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.version"], "single_key"),
        
        ("sbom_cyclonedx_field_002", "Verify the CycloneDX SBOM has a serialNumber.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    not sbom.serialNumber\n    result := \"CycloneDX SBOM has no serialNumber\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.serialNumber"], "single_key"),
        
        ("sbom_cyclonedx_field_003", "Verify the CycloneDX SBOM serialNumber starts with 'urn:uuid:'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    sbom.serialNumber\n    not startswith(sbom.serialNumber, \"urn:uuid:\")\n    result := sprintf(\"CycloneDX SBOM serialNumber has invalid format: %s\", [sbom.serialNumber])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.serialNumber"], "single_key"),
        
        ("sbom_cyclonedx_field_004", "Verify the CycloneDX SBOM metadata component has a bom-ref.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    sbom.metadata.component\n    not sbom.metadata.component[\"bom-ref\"]\n    result := \"CycloneDX SBOM metadata component has no bom-ref\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.component.bom-ref"], "single_key"),
    ]
    
    # More Validation Patterns
    validation_patterns = [
        ("sbom_spdx_validate_001", "Verify all packages in the SPDX SBOM have checksumValue with valid length for SHA256.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some chk in pkg.checksums\n    chk.algorithm == \"SHA256\"\n    count(chk.checksumValue) != 64\n    result := sprintf(\"Package %s has SHA256 checksum with invalid length: %d\", [pkg.name, count(chk.checksumValue)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.algorithm", "chk.checksumValue", "pkg.name"], "compound"),
        
        ("sbom_spdx_validate_002", "Verify all packages in the SPDX SBOM have checksumValue with valid length for SHA1.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some chk in pkg.checksums\n    chk.algorithm == \"SHA1\"\n    count(chk.checksumValue) != 40\n    result := sprintf(\"Package %s has SHA1 checksum with invalid length: %d\", [pkg.name, count(chk.checksumValue)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.checksums", "chk.algorithm", "chk.checksumValue", "pkg.name"], "compound"),
        
        ("sbom_spdx_validate_003", "Verify all files in the SPDX SBOM have checksumValue with valid length for SHA256.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some file in sbom.files\n    some chk in file.checksums\n    chk.algorithm == \"SHA256\"\n    count(chk.checksumValue) != 64\n    result := sprintf(\"File %s has SHA256 checksum with invalid length: %d\", [file.fileName, count(chk.checksumValue)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.files", "file.checksums", "chk.algorithm", "chk.checksumValue", "file.fileName"], "compound"),
        
        ("sbom_spdx_validate_004", "Verify all packages in the SPDX SBOM have packageVerificationCodeValue with valid length.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.packageVerificationCode\n    count(pkg.packageVerificationCode.packageVerificationCodeValue) != 40\n    result := sprintf(\"Package %s has packageVerificationCodeValue with invalid length: %d\", [pkg.name, count(pkg.packageVerificationCode.packageVerificationCodeValue)])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.packageVerificationCode", "pkg.packageVerificationCode.packageVerificationCodeValue", "pkg.name"], "compound"),
        
        ("sbom_cyclonedx_validate_001", "Verify all components in the CycloneDX SBOM have version format matching semver when applicable.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.version\n    contains(comp.version, \".\")\n    version_parts := split(comp.version, \".\")\n    count(version_parts) < 2\n    result := sprintf(\"Component %s has invalid semver format: %s\", [comp.name, comp.version])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.version", "comp.name"], "compound"),
    ]
    
    # Final Batch - Additional Variations
    final_batch = [
        ("sbom_spdx_final_001", "Verify the SPDX SBOM has packages with at least one having filesAnalyzed true.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    analyzed_count := count([pkg | some pkg in sbom.packages; pkg.filesAnalyzed == true])\n    analyzed_count == 0\n    result := \"SPDX SBOM has no packages with filesAnalyzed true\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.filesAnalyzed"], "compound"),
        
        ("sbom_spdx_final_002", "Verify all packages in the SPDX SBOM have downloadLocation not equal to empty string.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.downloadLocation == \"\"\n    result := sprintf(\"Package %s has empty downloadLocation\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.downloadLocation", "pkg.name"], "compound"),
        
        ("sbom_spdx_final_003", "Verify all packages in the SPDX SBOM have copyrightText not equal to empty string.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.copyrightText == \"\"\n    result := sprintf(\"Package %s has empty copyrightText\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.copyrightText", "pkg.name"], "compound"),
        
        ("sbom_spdx_final_004", "Verify the SPDX SBOM has at least one package with supplier containing 'Red Hat'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    suppliers := {pkg.supplier | some pkg in sbom.packages}\n    not any([contains(supplier, \"Red Hat\") | some supplier in suppliers])\n    result := \"SPDX SBOM has no packages with Red Hat supplier\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.supplier"], "compound"),
        
        ("sbom_spdx_final_005", "Verify all packages in the SPDX SBOM have versionInfo not equal to empty string.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    pkg.versionInfo == \"\"\n    result := sprintf(\"Package %s has empty versionInfo\", [pkg.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.versionInfo", "pkg.name"], "compound"),
        
        ("sbom_spdx_final_006", "Verify the SPDX SBOM has packages with at least one having a PURL containing 'rpm'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    rpm_purls := count([ref | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceType == \"purl\"; contains(ref.referenceLocator, \"rpm\")])\n    rpm_purls == 0\n    result := \"SPDX SBOM has no packages with RPM PURLs\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator"], "compound"),
        
        ("sbom_spdx_final_007", "Verify the SPDX SBOM has packages with at least one having a PURL containing 'golang'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    golang_purls := count([ref | some pkg in sbom.packages; some ref in pkg.externalRefs; ref.referenceType == \"purl\"; contains(ref.referenceLocator, \"golang\")])\n    golang_purls == 0\n    result := \"SPDX SBOM has no packages with Golang PURLs\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceType", "ref.referenceLocator"], "compound"),
        
        ("sbom_spdx_final_008", "Verify all packages in the SPDX SBOM have external references with referenceCategory in allowed categories.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://spdx.dev/Document\"\n    sbom := statement.predicate\n    some pkg in sbom.packages\n    some ref in pkg.externalRefs\n    ref.referenceCategory not in [\"SECURITY\", \"PACKAGE_MANAGER\", \"PERSISTENT_ID\", \"OTHER\"]\n    result := sprintf(\"Package %s has disallowed referenceCategory: %s\", [pkg.name, ref.referenceCategory])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.packages", "pkg.externalRefs", "ref.referenceCategory", "pkg.name"], "compound"),
        
        ("sbom_cyclonedx_final_001", "Verify all components in the CycloneDX SBOM have type in allowed component types.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.type not in [\"application\", \"library\", \"container\", \"file\", \"firmware\", \"operating-system\", \"device\", \"device-driver\", \"platform\", \"framework\"]\n    result := sprintf(\"Component %s has invalid type: %s\", [comp.name, comp.type])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.type", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_final_002", "Verify all components in the CycloneDX SBOM have externalReferences with type in allowed types.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    some ext_ref in comp.externalReferences\n    ext_ref.type not in [\"vcs\", \"issue-tracker\", \"website\", \"advisories\", \"bom\", \"mailing-list\", \"social\", \"chat\", \"documentation\", \"support\", \"distribution\", \"license\", \"build-meta\", \"build-system\", \"other\"]\n    result := sprintf(\"Component %s has disallowed externalReference type: %s\", [comp.name, ext_ref.type])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.externalReferences", "ext_ref.type", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_final_003", "Verify all components in the CycloneDX SBOM have a non-empty name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.name == \"\"\n    result := \"Component in CycloneDX SBOM has empty name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_final_004", "Verify the CycloneDX SBOM has components with at least one having type 'library'.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    library_count := count([comp | some comp in sbom.components; comp.type == \"library\"])\n    library_count == 0\n    result := \"CycloneDX SBOM has no components with type library\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.type"], "compound"),
        
        ("sbom_cyclonedx_final_005", "Verify all components in the CycloneDX SBOM have purl starting with 'pkg:' when present.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some comp in sbom.components\n    comp.purl\n    not startswith(comp.purl, \"pkg:\")\n    result := sprintf(\"Component %s has purl not starting with pkg:: %s\", [comp.name, comp.purl])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.components", "comp.purl", "comp.name"], "compound"),
        
        ("sbom_cyclonedx_final_006", "Verify the CycloneDX SBOM metadata component has a type in allowed types.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    sbom.metadata.component\n    sbom.metadata.component.type not in [\"application\", \"library\", \"container\", \"file\", \"firmware\", \"operating-system\", \"device\", \"device-driver\", \"platform\", \"framework\"]\n    result := sprintf(\"CycloneDX SBOM metadata component has invalid type: %s\", [sbom.metadata.component.type])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.component.type"], "single_key"),
        
        ("sbom_cyclonedx_final_007", "Verify all tools in the CycloneDX SBOM metadata have a non-empty name.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some tool in sbom.metadata.tools\n    tool.name == \"\"\n    result := \"Tool in CycloneDX SBOM metadata has empty name\"\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools", "tool.name"], "compound"),
        
        ("sbom_cyclonedx_final_008", "Verify all tools in the CycloneDX SBOM metadata have a non-empty vendor.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some tool in sbom.metadata.tools\n    tool.vendor == \"\"\n    result := sprintf(\"Tool %s in CycloneDX SBOM metadata has empty vendor\", [tool.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools", "tool.vendor", "tool.name"], "compound"),
        
        ("sbom_cyclonedx_final_009", "Verify all tools in the CycloneDX SBOM metadata have a non-empty version.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    some tool in sbom.metadata.tools\n    tool.version == \"\"\n    result := sprintf(\"Tool %s in CycloneDX SBOM metadata has empty version\", [tool.name])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.metadata.tools", "tool.version", "tool.name"], "compound"),
        
        ("sbom_cyclonedx_final_010", "Verify the CycloneDX SBOM has a specVersion matching '1.' pattern.",
         "deny contains result if {\n    some att in input.attestations\n    statement := att.statement\n    statement.predicateType == \"https://cyclonedx.org/bom\"\n    sbom := statement.predicate\n    sbom.specVersion\n    not startswith(sbom.specVersion, \"1.\")\n    result := sprintf(\"CycloneDX SBOM has invalid specVersion format: %s\", [sbom.specVersion])\n}",
         ["input.attestations", "statement.predicateType", "statement.predicate.specVersion"], "single_key"),
    ]
    
    # Combine all test cases
    all_cases = (spdx_doc_cases + spdx_pkg_cases + spdx_file_cases + cyclonedx_doc_cases + cyclonedx_comp_cases + 
                 complex_patterns + spdx_pkg_variations + spdx_file_variations + spdx_doc_variations + 
                 cyclonedx_comp_variations + cyclonedx_doc_variations + more_complex_patterns +
                 spdx_pkg_more + spdx_file_more + cyclonedx_comp_more + edge_cases + pattern_matching + count_validations +
                 spdx_advanced + field_presence + validation_patterns + final_batch)
    
    for case_id, natural_language, rego_code, keys_used, case_type in all_cases:
        test_cases[case_id] = generate_test_case(case_id, natural_language, rego_code, keys_used, case_type)
    
    # Count types
    single_key_count = sum(1 for tc in test_cases.values() if tc["type"] == "single_key")
    compound_count = sum(1 for tc in test_cases.values() if tc["type"] == "compound")
    
    return {
        "metadata": {
            "total_test_cases": len(test_cases),
            "single_key_cases": single_key_count,
            "compound_cases": compound_count,
            "rules": [
                "ALL rules start with: some att in input.attestations",
                "NEVER reuse 'result' variable - reserved for deny output",
                "Use descriptive variable names for loops (pkg, ref, comp, file, chk, etc.)",
                "Access SBOMs directly from attestations by checking predicateType",
                "For SPDX: statement.predicateType == \"https://spdx.dev/Document\"",
                "For CycloneDX: statement.predicateType == \"https://cyclonedx.org/bom\"",
                "Use pure Rego - no library imports"
            ]
        },
        "test_cases": test_cases
    }

def main():
    """Generate comprehensive SBOM test cases."""
    project_root = Path(__file__).parent.parent.parent
    output_file = project_root / "sbom_data" / "comprehensive_test_cases.json"
    
    print("Generating comprehensive SBOM test cases...")
    test_cases = generate_all_sbom_test_cases()
    
    # Load existing test cases if they exist
    existing_cases = {}
    if output_file.exists():
        with open(output_file, 'r') as f:
            existing_data = json.load(f)
            existing_cases = existing_data.get("test_cases", {})
            print(f"Found {len(existing_cases)} existing test cases")
    
    # Merge: new cases override existing ones with same ID
    merged_cases = {**existing_cases, **test_cases["test_cases"]}
    
    # Update metadata
    single_key_count = sum(1 for tc in merged_cases.values() if tc["type"] == "single_key")
    compound_count = sum(1 for tc in merged_cases.values() if tc["type"] == "compound")
    
    output_data = {
        "metadata": {
            "total_test_cases": len(merged_cases),
            "single_key_cases": single_key_count,
            "compound_cases": compound_count,
            "rules": test_cases["metadata"]["rules"]
        },
        "test_cases": merged_cases
    }
    
    # Write output
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n✅ Generated {len(test_cases['test_cases'])} new test cases")
    print(f"   Total test cases: {len(merged_cases)}")
    print(f"   Single key cases: {single_key_count}")
    print(f"   Compound cases: {compound_count}")
    print(f"   Output: {output_file}")

if __name__ == "__main__":
    main()
