#
# METADATA
# title: Verify all relationships in the SPDX SBOM have relationshipType.
# description: >-
#   Verify all relationships in the SPDX SBOM have relationshipType.
# custom:
#   short_name: sbom_spdx_adv_007
#   failure_msg: Policy validation failed
#
package sbom_spdx_adv_007

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some rel in sbom.relationships
    not rel.relationshipType
    result := "Relationship in SPDX SBOM has no relationshipType"
}
