#
# METADATA
# title: Verify the SPDX SBOM contains files.
# description: >-
#   Verify the SPDX SBOM contains files.
# custom:
#   short_name: sbom_spdx_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.files) == 0
    result := "SPDX SBOM has no files"
}
