#
# METADATA
# title: Verify the CycloneDX SBOM has at least one attestation with predicateType 'https://cyclonedx.org/bom'.
# description: >-
#   Verify the CycloneDX SBOM has at least one attestation with predicateType 'https://cyclonedx.org/bom'.
# custom:
#   short_name: sbom_cyclonedx_edge_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_edge_001

import rego.v1

deny contains result if {
    cyclonedx_count := count([att | some att in input.attestations; att.statement.predicateType == "https://cyclonedx.org/bom"])
    cyclonedx_count == 0
    result := "No CycloneDX SBOM attestations found"
}
