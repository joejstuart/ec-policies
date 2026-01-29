#
# METADATA
# title: Verify all relationships in the SPDX SBOM have relatedSpdxElement.
# description: >-
#   Verify all relationships in the SPDX SBOM have relatedSpdxElement.
# custom:
#   short_name: sbom_spdx_adv_006
#   failure_msg: Policy validation failed
#
package sbom_spdx_adv_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some rel in sbom.relationships
    not rel.relatedSpdxElement
    result := "Relationship in SPDX SBOM has no relatedSpdxElement"
}
