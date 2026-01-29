#
# METADATA
# title: Verify the CycloneDX SBOM metadata has at least one tool.
# description: >-
#   Verify the CycloneDX SBOM metadata has at least one tool.
# custom:
#   short_name: sbom_cyclonedx_count_003
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_count_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    count(sbom.metadata.tools) < 1
    result := "CycloneDX SBOM metadata has no tools"
}
