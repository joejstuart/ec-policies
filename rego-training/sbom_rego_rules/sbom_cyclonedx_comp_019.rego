#
# METADATA
# title: Verify all components in the CycloneDX SBOM have externalReferences with valid url format.
# description: >-
#   Verify all components in the CycloneDX SBOM have externalReferences with valid url format.
# custom:
#   short_name: sbom_cyclonedx_comp_019
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_019

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    some ext_ref in comp.externalReferences
    ext_ref.url
    not startswith(ext_ref.url, "http")
    result := sprintf("Component %s has externalReference with invalid url format: %s", [comp.name, ext_ref.url])
}
