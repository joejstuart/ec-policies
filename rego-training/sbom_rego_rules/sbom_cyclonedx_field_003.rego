#
# METADATA
# title: Verify the CycloneDX SBOM serialNumber starts with 'urn:uuid:'.
# description: >-
#   Verify the CycloneDX SBOM serialNumber starts with 'urn:uuid:'.
# custom:
#   short_name: sbom_cyclonedx_field_003
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_field_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    sbom.serialNumber
    not startswith(sbom.serialNumber, "urn:uuid:")
    result := sprintf("CycloneDX SBOM serialNumber has invalid format: %s", [sbom.serialNumber])
}
