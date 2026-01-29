#
# METADATA
# title: Verify all tools in the CycloneDX SBOM metadata have a non-empty name.
# description: >-
#   Verify all tools in the CycloneDX SBOM metadata have a non-empty name.
# custom:
#   short_name: sbom_cyclonedx_final_007
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_007

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some tool in sbom.metadata.tools
    tool.name == ""
    result := "Tool in CycloneDX SBOM metadata has empty name"
}
