#
# METADATA
# title: Verify the CycloneDX SBOM metadata component has a name.
# description: >-
#   Verify the CycloneDX SBOM metadata component has a name.
# custom:
#   short_name: sbom_cyclonedx_doc_007
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_007

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    not sbom.metadata.component.name
    result := "CycloneDX SBOM metadata component has no name"
}
