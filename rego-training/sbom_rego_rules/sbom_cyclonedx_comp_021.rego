#
# METADATA
# title: Verify all components in the CycloneDX SBOM have valid type values.
# description: >-
#   Verify all components in the CycloneDX SBOM have valid type values.
# custom:
#   short_name: sbom_cyclonedx_comp_021
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_021

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    not (comp.type in ["application", "library", "container", "file", "firmware", "operating-system"])
    result := sprintf("Component %s has invalid type: %s", [comp.name, comp.type])
}
