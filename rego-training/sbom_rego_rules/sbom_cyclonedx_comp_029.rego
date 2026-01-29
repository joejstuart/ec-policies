#
# METADATA
# title: Verify all components in the CycloneDX SBOM have licenses with unique names.
# description: >-
#   Verify all components in the CycloneDX SBOM have licenses with unique names.
# custom:
#   short_name: sbom_cyclonedx_comp_029
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_029

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    license_names := {lic.license.name | some lic in comp.licenses; lic.license.name}
    license_count := count([lic | some lic in comp.licenses; lic.license.name])
    count(license_names) != license_count
    result := sprintf("Component %s has duplicate license names", [comp.name])
}
