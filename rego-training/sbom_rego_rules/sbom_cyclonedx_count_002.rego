#
# METADATA
# title: Verify all components in the CycloneDX SBOM have at least one license.
# description: >-
#   Verify all components in the CycloneDX SBOM have at least one license.
# custom:
#   short_name: sbom_cyclonedx_count_002
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_count_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    count(comp.licenses) < 1
    result := sprintf("Component %s has no licenses", [comp.name])
}
