#
# METADATA
# title: Verify all components in the CycloneDX SBOM have unique purls.
# description: >-
#   Verify all components in the CycloneDX SBOM have unique purls.
# custom:
#   short_name: sbom_cyclonedx_comp_024
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_024

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    comp_purls := {comp.purl | some comp in sbom.components; comp.purl}
    purl_count := count([comp | some comp in sbom.components; comp.purl])
    count(comp_purls) != purl_count
    result := "CycloneDX SBOM has duplicate component purls"
}
