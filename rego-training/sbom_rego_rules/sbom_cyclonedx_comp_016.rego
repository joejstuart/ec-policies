#
# METADATA
# title: Verify all components in the CycloneDX SBOM have properties with a name.
# description: >-
#   Verify all components in the CycloneDX SBOM have properties with a name.
# custom:
#   short_name: sbom_cyclonedx_comp_016
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_016

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    some prop in comp.properties
    not prop.name
    result := sprintf("Component %s has property with no name", [comp.name])
}
