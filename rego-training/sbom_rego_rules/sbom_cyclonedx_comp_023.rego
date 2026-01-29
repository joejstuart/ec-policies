#
# METADATA
# title: Verify all components in the CycloneDX SBOM have unique names.
# description: >-
#   Verify all components in the CycloneDX SBOM have unique names.
# custom:
#   short_name: sbom_cyclonedx_comp_023
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_023

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    comp_names := {comp.name | some comp in sbom.components}
    count(comp_names) != count(sbom.components)
    result := "CycloneDX SBOM has duplicate component names"
}
