#
# METADATA
# title: Verify all components in the CycloneDX SBOM have externalReferences with a url.
# description: >-
#   Verify all components in the CycloneDX SBOM have externalReferences with a url.
# custom:
#   short_name: sbom_cyclonedx_comp_018
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_018

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    some ext_ref in comp.externalReferences
    not ext_ref.url
    result := sprintf("Component %s has externalReference with no url", [comp.name])
}
