#
# METADATA
# title: Verify the SPDX SBOM has at least 5 files.
# description: >-
#   Verify the SPDX SBOM has at least 5 files.
# custom:
#   short_name: sbom_spdx_count_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_count_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.files) < 5
    result := sprintf("SPDX SBOM has only %d files, expected at least 5", [count(sbom.files)])
}
