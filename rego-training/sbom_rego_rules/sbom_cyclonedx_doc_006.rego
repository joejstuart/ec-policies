#
# METADATA
# title: Verify the CycloneDX SBOM metadata has a component.
# description: >-
#   Verify the CycloneDX SBOM metadata has a component.
# custom:
#   short_name: sbom_cyclonedx_doc_006
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    not sbom.metadata.component
    result := "CycloneDX SBOM metadata has no component"
}
