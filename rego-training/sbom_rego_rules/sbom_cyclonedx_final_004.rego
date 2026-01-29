#
# METADATA
# title: Verify the CycloneDX SBOM has components with at least one having type 'library'.
# description: >-
#   Verify the CycloneDX SBOM has components with at least one having type 'library'.
# custom:
#   short_name: sbom_cyclonedx_final_004
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    library_count := count([comp | some comp in sbom.components; comp.type == "library"])
    library_count == 0
    result := "CycloneDX SBOM has no components with type library"
}
