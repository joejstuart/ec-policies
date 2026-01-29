#
# METADATA
# title: Verify all components in the CycloneDX SBOM have purl containing '@' when version exists.
# description: >-
#   Verify all components in the CycloneDX SBOM have purl containing '@' when version exists.
# custom:
#   short_name: sbom_cyclonedx_pattern_001
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_pattern_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    comp.purl
    comp.version
    not contains(comp.purl, "@")
    result := sprintf("Component %s has purl without @ despite having version: %s", [comp.name, comp.purl])
}
