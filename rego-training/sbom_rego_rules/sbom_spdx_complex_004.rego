#
# METADATA
# title: Verify the SPDX SBOM documentNamespace contains 'spdxdocs'.
# description: >-
#   Verify the SPDX SBOM documentNamespace contains 'spdxdocs'.
# custom:
#   short_name: sbom_spdx_complex_004
#   failure_msg: Policy validation failed
#
package sbom_spdx_complex_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not contains(sbom.documentNamespace, "spdxdocs")
    result := sprintf("SPDX SBOM documentNamespace %s does not contain spdxdocs", [sbom.documentNamespace])
}
