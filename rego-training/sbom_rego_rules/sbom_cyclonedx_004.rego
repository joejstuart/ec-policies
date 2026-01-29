#
# METADATA
# title: Verify all components in the CycloneDX SBOM are of type 'library'.
# description: >-
#   Verify all components in the CycloneDX SBOM are of type 'library'.
# custom:
#   short_name: sbom_cyclonedx_004
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_004

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.type != "library"
    result := sprintf("Component %s has type %s, expected library", [comp.name, comp.type])
}
