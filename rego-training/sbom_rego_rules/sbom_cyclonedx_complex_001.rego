#
# METADATA
# title: Verify the CycloneDX SBOM metadata has a timestamp.
# description: >-
#   Verify the CycloneDX SBOM metadata has a timestamp.
# custom:
#   short_name: sbom_cyclonedx_complex_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_complex_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    not sbom.metadata.timestamp
    result := "CycloneDX SBOM metadata has no timestamp"
}
