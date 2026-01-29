#
# METADATA
# title: Verify all components in the CycloneDX SBOM have properties.
# description: >-
#   Verify all components in the CycloneDX SBOM have properties.
# custom:
#   short_name: sbom_cyclonedx_comp_010
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_010

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    count(comp.properties) == 0
    result := sprintf("Component %s has no properties", [comp.name])
}
