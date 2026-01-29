#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a cpe.
# description: >-
#   Verify all components in the CycloneDX SBOM have a cpe.
# custom:
#   short_name: sbom_cyclonedx_comp_009
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_009

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    not comp.cpe
    result := sprintf("Component %s has no cpe", [comp.name])
}
