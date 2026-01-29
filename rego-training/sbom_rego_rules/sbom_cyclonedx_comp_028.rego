#
# METADATA
# title: Verify all components in the CycloneDX SBOM have externalReferences with unique types.
# description: >-
#   Verify all components in the CycloneDX SBOM have externalReferences with unique types.
# custom:
#   short_name: sbom_cyclonedx_comp_028
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_comp_028

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some comp in sbom.components
    ext_ref_types := {ext_ref.type | some ext_ref in comp.externalReferences}
    count(ext_ref_types) != count(comp.externalReferences)
    result := sprintf("Component %s has duplicate externalReference types", [comp.name])
}
