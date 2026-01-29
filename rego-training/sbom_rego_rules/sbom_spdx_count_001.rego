#
# METADATA
# title: Verify the SPDX SBOM has at least 10 packages.
# description: >-
#   Verify the SPDX SBOM has at least 10 packages.
# custom:
#   short_name: sbom_spdx_count_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_count_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.packages) < 10
    result := sprintf("SPDX SBOM has only %d packages, expected at least 10", [count(sbom.packages)])
}
