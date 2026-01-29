#
# METADATA
# title: Verify the CycloneDX SBOM metadata component has a type in allowed types.
# description: >-
#   Verify the CycloneDX SBOM metadata component has a type in allowed types.
# custom:
#   short_name: sbom_cyclonedx_final_006
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    sbom.metadata.component
    not (sbom.metadata.component.type in ["application", "library", "container", "file", "firmware", "operating-system", "device", "device-driver", "platform", "framework"])
    result := sprintf("CycloneDX SBOM metadata component has invalid type: %s", [sbom.metadata.component.type])
}
