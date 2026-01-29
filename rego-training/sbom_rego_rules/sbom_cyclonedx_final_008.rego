#
# METADATA
# title: Verify all tools in the CycloneDX SBOM metadata have a non-empty vendor.
# description: >-
#   Verify all tools in the CycloneDX SBOM metadata have a non-empty vendor.
# custom:
#   short_name: sbom_cyclonedx_final_008
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_008

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some tool in sbom.metadata.tools
    tool.vendor == ""
    result := sprintf("Tool %s in CycloneDX SBOM metadata has empty vendor", [tool.name])
}
