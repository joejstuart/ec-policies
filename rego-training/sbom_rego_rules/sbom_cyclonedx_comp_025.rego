#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a non-empty name.
# description: >-
#   Verify all components in the CycloneDX SBOM have a non-empty name.
# custom:
#   short_name: sbom_cyclonedx_comp_025
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_025

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.name == ""
    result := "Component in CycloneDX SBOM has empty name"
}
