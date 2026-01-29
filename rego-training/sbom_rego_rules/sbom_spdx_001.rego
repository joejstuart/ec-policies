#
# METADATA
# title: Verify the SPDX SBOM contains packages.
# description: >-
#   Verify the SPDX SBOM contains packages.
# custom:
#   short_name: sbom_spdx_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    count(sbom.packages) == 0
    result := "SPDX SBOM has no packages"
}
