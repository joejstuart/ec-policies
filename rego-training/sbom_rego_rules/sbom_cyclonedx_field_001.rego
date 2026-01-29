#
# METADATA
# title: Verify the CycloneDX SBOM has a version field.
# description: >-
#   Verify the CycloneDX SBOM has a version field.
# custom:
#   short_name: sbom_cyclonedx_field_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_field_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    not sbom.version
    result := "CycloneDX SBOM has no version field"
}
