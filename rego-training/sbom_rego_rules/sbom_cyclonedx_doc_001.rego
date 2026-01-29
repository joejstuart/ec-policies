#
# METADATA
# title: Verify the CycloneDX SBOM has a valid bomFormat.
# description: >-
#   Verify the CycloneDX SBOM has a valid bomFormat.
# custom:
#   short_name: sbom_cyclonedx_doc_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    sbom.bomFormat != "CycloneDX"
    result := sprintf("CycloneDX SBOM has invalid bomFormat: %s", [sbom.bomFormat])
}
