#
# METADATA
# title: Verify all components in the CycloneDX SBOM have a valid purl format.
# description: >-
#   Verify all components in the CycloneDX SBOM have a valid purl format.
# custom:
#   short_name: sbom_cyclonedx_comp_012
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_012

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.purl
    not startswith(comp.purl, "pkg:")
    result := sprintf("Component %s has invalid purl format: %s", [comp.name, comp.purl])
}
