#
# METADATA
# title: Verify the CycloneDX SBOM has at least 10 components.
# description: >-
#   Verify the CycloneDX SBOM has at least 10 components.
# custom:
#   short_name: sbom_cyclonedx_count_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_count_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    count(sbom.components) < 10
    result := sprintf("CycloneDX SBOM has only %d components, expected at least 10", [count(sbom.components)])
}
