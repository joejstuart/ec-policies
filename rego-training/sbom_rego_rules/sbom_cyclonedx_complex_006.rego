#
# METADATA
# title: Verify all components in the CycloneDX SBOM with purl have valid purl type.
# description: >-
#   Verify all components in the CycloneDX SBOM with purl have valid purl type.
# custom:
#   short_name: sbom_cyclonedx_complex_006
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_complex_006

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.purl
    purl_parts := split(comp.purl, "/")
    count(purl_parts) < 2
    result := sprintf("Component %s has invalid purl structure: %s", [comp.name, comp.purl])
}
