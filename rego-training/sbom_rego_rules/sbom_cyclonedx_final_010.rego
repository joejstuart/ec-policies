#
# METADATA
# title: Verify the CycloneDX SBOM has a specVersion matching '1.' pattern.
# description: >-
#   Verify the CycloneDX SBOM has a specVersion matching '1.' pattern.
# custom:
#   short_name: sbom_cyclonedx_final_010
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_010

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    sbom.specVersion
    not startswith(sbom.specVersion, "1.")
    result := sprintf("CycloneDX SBOM has invalid specVersion format: %s", [sbom.specVersion])
}
