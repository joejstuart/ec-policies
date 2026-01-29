#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a valid cpe format.
# description: >-
#   Verify all components in the CycloneDX SBOM have a valid cpe format.
# custom:
#   short_name: sbom_cyclonedx_comp_013
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_013

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.cpe
    not startswith(comp.cpe, "cpe:")
    result := sprintf("Component %s has invalid cpe format: %s", [comp.name, comp.cpe])
}
