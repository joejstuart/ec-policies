#
# METADATA
# title: Verify the SPDX SBOM has a documentNamespace.
# description: >-
#   Verify the SPDX SBOM has a documentNamespace.
# custom:
#   short_name: sbom_spdx_doc_004
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not sbom.documentNamespace
    result := "SPDX SBOM has no documentNamespace"
}
