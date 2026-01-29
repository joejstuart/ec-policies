#
# METADATA
# title: Verify the SPDX SBOM has creation info.
# description: >-
#   Verify the SPDX SBOM has creation info.
# custom:
#   short_name: sbom_spdx_doc_006
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not sbom.creationInfo
    result := "SPDX SBOM has no creationInfo"
}
