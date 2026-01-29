#
# METADATA
# title: Verify all components in the CycloneDX SBOM have cpe containing 'cpe:2.3:'.
# description: >-
#   Verify all components in the CycloneDX SBOM have cpe containing 'cpe:2.3:'.
# custom:
#   short_name: sbom_cyclonedx_pattern_002
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_pattern_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.cpe
    not contains(comp.cpe, "cpe:2.3:")
    result := sprintf("Component %s has invalid cpe format: %s", [comp.name, comp.cpe])
}
