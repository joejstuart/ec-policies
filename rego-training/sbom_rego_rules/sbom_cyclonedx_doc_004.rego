#
# METADATA
# title: Verify the CycloneDX SBOM has metadata.
# description: >-
#   Verify the CycloneDX SBOM has metadata.
# custom:
#   short_name: sbom_cyclonedx_doc_004
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    not sbom.metadata
    result := "CycloneDX SBOM has no metadata"
}
