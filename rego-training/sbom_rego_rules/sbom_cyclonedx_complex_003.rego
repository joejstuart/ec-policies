#
# METADATA
# title: Verify all tools in the CycloneDX SBOM metadata have a name.
# description: >-
#   Verify all tools in the CycloneDX SBOM metadata have a name.
# custom:
#   short_name: sbom_cyclonedx_complex_003
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_complex_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some tool in sbom.metadata.tools
    not tool.name
    result := "Tool in CycloneDX SBOM metadata has no name"
}
