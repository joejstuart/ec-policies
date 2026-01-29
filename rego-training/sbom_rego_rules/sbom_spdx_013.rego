#
# METADATA
# title: Verify the SPDX SBOM has at least one creator.
# description: >-
#   Verify the SPDX SBOM has at least one creator.
# custom:
#   short_name: sbom_spdx_013
#   failure_msg: Policy validation failed
#
package sbom_spdx_013

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.creationInfo.creators) == 0
    result := "SPDX SBOM has no creators"
}
