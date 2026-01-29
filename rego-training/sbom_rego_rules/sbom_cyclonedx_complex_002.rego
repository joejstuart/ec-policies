#
# METADATA
# title: Verify the CycloneDX SBOM metadata has tools.
# description: >-
#   Verify the CycloneDX SBOM metadata has tools.
# custom:
#   short_name: sbom_cyclonedx_complex_002
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_complex_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    count(sbom.metadata.tools) == 0
    result := "CycloneDX SBOM metadata has no tools"
}
