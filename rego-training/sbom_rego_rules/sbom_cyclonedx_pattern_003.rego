#
# METADATA
# title: Verify all tools in the CycloneDX SBOM metadata have name containing at least one letter.
# description: >-
#   Verify all tools in the CycloneDX SBOM metadata have name containing at least one letter.
# custom:
#   short_name: sbom_cyclonedx_pattern_003
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_pattern_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some tool in sbom.metadata.tools
    not regex.match("[a-zA-Z]", tool.name)
    result := sprintf("Tool %s has name without letters", [tool.name])
}
