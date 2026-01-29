#
# METADATA
# title: Verify all components in the CycloneDX SBOM have externalReferences.
# description: >-
#   Verify all components in the CycloneDX SBOM have externalReferences.
# custom:
#   short_name: sbom_cyclonedx_comp_011
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_011

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    count(comp.externalReferences) == 0
    result := sprintf("Component %s has no externalReferences", [comp.name])
}
