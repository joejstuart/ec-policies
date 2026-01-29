#
# METADATA
# title: Verify all components in the CycloneDX SBOM have purl starting with 'pkg:' when present.
# description: >-
#   Verify all components in the CycloneDX SBOM have purl starting with 'pkg:' when present.
# custom:
#   short_name: sbom_cyclonedx_final_005
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.purl
    not startswith(comp.purl, "pkg:")
    result := sprintf("Component %s has purl not starting with pkg:: %s", [comp.name, comp.purl])
}
