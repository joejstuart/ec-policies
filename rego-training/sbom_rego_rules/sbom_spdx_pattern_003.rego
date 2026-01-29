#
# METADATA
# title: Verify the SPDX SBOM name matches expected image reference pattern.
# description: >-
#   Verify the SPDX SBOM name matches expected image reference pattern.
# custom:
#   short_name: sbom_spdx_pattern_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_pattern_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    not contains(sbom.name, "@")
    result := sprintf("SPDX SBOM name does not match image reference pattern: %s", [sbom.name])
}
