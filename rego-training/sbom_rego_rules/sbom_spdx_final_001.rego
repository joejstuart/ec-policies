#
# METADATA
# title: Verify the SPDX SBOM has packages with at least one having filesAnalyzed true.
# description: >-
#   Verify the SPDX SBOM has packages with at least one having filesAnalyzed true.
# custom:
#   short_name: sbom_spdx_final_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_final_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    analyzed_count := count([pkg | some pkg in sbom.packages; pkg.filesAnalyzed == true])
    analyzed_count == 0
    result := "SPDX SBOM has no packages with filesAnalyzed true"
}
