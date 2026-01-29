#
# METADATA
# title: Verify all components in the CycloneDX SBOM have licenses with a name.
# description: >-
#   Verify all components in the CycloneDX SBOM have licenses with a name.
# custom:
#   short_name: sbom_cyclonedx_comp_015
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_015

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    some license_entry in comp.licenses
    license_entry.license
    not license_entry.license.name
    result := sprintf("Component %s has license with no name", [comp.name])
}
