#
# METADATA
# title: Verify all components in the CycloneDX SBOM have properties with unique names.
# description: >-
#   Verify all components in the CycloneDX SBOM have properties with unique names.
# custom:
#   short_name: sbom_cyclonedx_comp_027
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_027

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    prop_names := {prop.name | some prop in comp.properties}
    count(prop_names) != count(comp.properties)
    result := sprintf("Component %s has duplicate property names", [comp.name])
}
