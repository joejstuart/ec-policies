#
# METADATA
# title: Verify the SPDX SBOM creationInfo created timestamp is valid ISO 8601.
# description: >-
#   Verify the SPDX SBOM creationInfo created timestamp is valid ISO 8601.
# custom:
#   short_name: sbom_spdx_doc_014
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_014

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not contains(sbom.creationInfo.created, "T")
    result := sprintf("SPDX SBOM creation timestamp is not valid ISO 8601: %s", [sbom.creationInfo.created])
}
