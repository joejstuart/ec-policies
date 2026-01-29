#
# METADATA
# title: Verify the CycloneDX SBOM metadata component has a bom-ref.
# description: >-
#   Verify the CycloneDX SBOM metadata component has a bom-ref.
# custom:
#   short_name: sbom_cyclonedx_field_004
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_field_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    sbom.metadata.component
    not sbom.metadata.component["bom-ref"]
    result := "CycloneDX SBOM metadata component has no bom-ref"
}
