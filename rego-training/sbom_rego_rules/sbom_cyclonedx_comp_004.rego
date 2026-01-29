#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a version.
# description: >-
#   Verify all components in the CycloneDX SBOM have a version.
# custom:
#   short_name: sbom_cyclonedx_comp_004
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    not comp.version
    result := sprintf("Component %s has no version", [comp.name])
}
