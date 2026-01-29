#
# METADATA
# title: Verify no components in the CycloneDX SBOM have empty version.
# description: >-
#   Verify no components in the CycloneDX SBOM have empty version.
# custom:
#   short_name: sbom_cyclonedx_comp_020
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_020

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.version == ""
    result := sprintf("Component %s has empty version", [comp.name])
}
