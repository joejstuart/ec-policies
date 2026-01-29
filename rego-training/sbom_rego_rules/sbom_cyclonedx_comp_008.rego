#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a publisher.
# description: >-
#   Verify all components in the CycloneDX SBOM have a publisher.
# custom:
#   short_name: sbom_cyclonedx_comp_008
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_008

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    not comp.publisher
    result := sprintf("Component %s has no publisher", [comp.name])
}
