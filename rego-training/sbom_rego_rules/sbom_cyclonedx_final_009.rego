#
# METADATA
# title: Verify all tools in the CycloneDX SBOM metadata have a non-empty version.
# description: >-
#   Verify all tools in the CycloneDX SBOM metadata have a non-empty version.
# custom:
#   short_name: sbom_cyclonedx_final_009
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_009

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some tool in sbom.metadata.tools
    tool.version == ""
    result := sprintf("Tool %s in CycloneDX SBOM metadata has empty version", [tool.name])
}
