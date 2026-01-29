#
# METADATA
# title: Verify all components in the CycloneDX SBOM have licenses with valid structure.
# description: >-
#   Verify all components in the CycloneDX SBOM have licenses with valid structure.
# custom:
#   short_name: sbom_cyclonedx_comp_014
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_014

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    some license_entry in comp.licenses
    not license_entry.license
    result := sprintf("Component %s has license entry with no license object", [comp.name])
}
