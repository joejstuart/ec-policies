#
# METADATA
# title: Verify the SPDX SBOM has relationships.
# description: >-
#   Verify the SPDX SBOM has relationships.
# custom:
#   short_name: sbom_spdx_adv_004
#   failure_msg: Policy validation failed
#
package sbom_spdx_adv_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.relationships) == 0
    result := "SPDX SBOM has no relationships"
}
