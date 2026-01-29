#
# METADATA
# title: Verify the CycloneDX SBOM has components with at least one purl type.
# description: >-
#   Verify the CycloneDX SBOM has components with at least one purl type.
# custom:
#   short_name: sbom_cyclonedx_complex_005
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_complex_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    purl_types := {split(comp.purl, "/")[1] | some comp in sbom.components; comp.purl}
    count(purl_types) == 0
    result := "CycloneDX SBOM has no components with purl types"
}
