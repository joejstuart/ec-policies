#
# METADATA
# title: Verify all components in the CycloneDX SBOM have unique bom-refs.
# description: >-
#   Verify all components in the CycloneDX SBOM have unique bom-refs.
# custom:
#   short_name: sbom_cyclonedx_comp_022
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_022

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    bom_refs := {comp["bom-ref"] | some comp in sbom.components}
    count(bom_refs) != count(sbom.components)
    result := "CycloneDX SBOM has duplicate bom-refs"
}
