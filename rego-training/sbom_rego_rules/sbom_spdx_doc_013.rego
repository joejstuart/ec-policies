#
# METADATA
# title: Verify all creators in the SPDX SBOM have a valid format.
# description: >-
#   Verify all creators in the SPDX SBOM have a valid format.
# custom:
#   short_name: sbom_spdx_doc_013
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_013

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some creator in sbom.creationInfo.creators
    not contains(creator, ":")
    result := sprintf("SPDX SBOM has invalid creator format: %s", [creator])
}
