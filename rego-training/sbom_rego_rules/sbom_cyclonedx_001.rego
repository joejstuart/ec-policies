#
# METADATA
# title: Verify the CycloneDX SBOM contains components.
# description: >-
#   Verify the CycloneDX SBOM contains components.
# custom:
#   short_name: sbom_cyclonedx_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    count(sbom.components) == 0
    result := "CycloneDX SBOM has no components"
}
