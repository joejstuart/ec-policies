#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a non-empty bom-ref.
# description: >-
#   Verify all components in the CycloneDX SBOM have a non-empty bom-ref.
# custom:
#   short_name: sbom_cyclonedx_comp_026
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_026

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp["bom-ref"] == ""
    result := sprintf("Component %s has empty bom-ref", [comp.name])
}
