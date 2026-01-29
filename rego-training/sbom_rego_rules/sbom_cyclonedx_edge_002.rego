#
# METADATA
# title: Verify all CycloneDX SBOMs have unique serialNumbers.
# description: >-
#   Verify all CycloneDX SBOMs have unique serialNumbers.
# custom:
#   short_name: sbom_cyclonedx_edge_002
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_edge_002

import rego.v1

deny contains result if {
    serial_numbers := {sbom.serialNumber | some att in input.attestations; statement := att.statement; statement.predicateType == "https://cyclonedx.org/bom"; sbom := statement.predicate; sbom.serialNumber}
    sbom_count := count([att | some att in input.attestations; att.statement.predicateType == "https://cyclonedx.org/bom"])
    count(serial_numbers) != sbom_count
    result := "CycloneDX SBOMs have duplicate serialNumbers"
}
