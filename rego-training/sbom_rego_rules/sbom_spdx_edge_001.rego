#
# METADATA
# title: Verify the SPDX SBOM has at least one attestation with predicateType 'https://spdx.dev/Document'.
# description: >-
#   Verify the SPDX SBOM has at least one attestation with predicateType 'https://spdx.dev/Document'.
# custom:
#   short_name: sbom_spdx_edge_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_edge_001

import rego.v1

deny contains result if {
    spdx_count := count([att | some att in input.attestations; att.statement.predicateType == "https://spdx.dev/Document"])
    spdx_count == 0
    result := "No SPDX SBOM attestations found"
}
