#
# METADATA
# title: Verify all SPDX SBOMs have unique names.
# description: >-
#   Verify all SPDX SBOMs have unique names.
# custom:
#   short_name: sbom_spdx_edge_002
#   failure_msg: Policy validation failed
#
package sbom_spdx_edge_002

import rego.v1

deny contains result if {
    sbom_names := {sbom.name | some att in input.attestations; statement := att.statement; statement.predicateType == "https://spdx.dev/Document"; sbom := statement.predicate}
    sbom_count := count([att | some att in input.attestations; att.statement.predicateType == "https://spdx.dev/Document"])
    count(sbom_names) != sbom_count
    result := "SPDX SBOMs have duplicate names"
}
