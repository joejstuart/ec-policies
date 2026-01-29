#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a type.
# description: >-
#   Verify all components in the CycloneDX SBOM have a type.
# custom:
#   short_name: sbom_cyclonedx_003
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    not comp.type
    result := sprintf("Component %s has no type", [comp.name])
}
