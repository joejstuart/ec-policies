#
# METADATA
# title: Verify all components in the CycloneDX SBOM have externalReferences with type in allowed types.
# description: >-
#   Verify all components in the CycloneDX SBOM have externalReferences with type in allowed types.
# custom:
#   short_name: sbom_cyclonedx_final_002
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_final_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    some ext_ref in comp.externalReferences
    not (ext_ref.type in ["vcs", "issue-tracker", "website", "advisories", "bom", "mailing-list", "social", "chat", "documentation", "support", "distribution", "license", "build-meta", "build-system", "other"])
    result := sprintf("Component %s has disallowed externalReference type: %s", [comp.name, ext_ref.type])
}
