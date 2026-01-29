#
# METADATA
# title: Verify the SPDX SBOM has a name.
# description: >-
#   Verify the SPDX SBOM has a name.
# custom:
#   short_name: sbom_spdx_doc_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not sbom.name
    result := "SPDX SBOM has no name"
}
