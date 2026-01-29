#
# METADATA
# title: Verify the SPDX SBOM documentNamespace is a valid URL.
# description: >-
#   Verify the SPDX SBOM documentNamespace is a valid URL.
# custom:
#   short_name: sbom_spdx_doc_011
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_011

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not startswith(sbom.documentNamespace, "http")
    result := sprintf("SPDX SBOM documentNamespace is not a valid URL: %s", [sbom.documentNamespace])
}
