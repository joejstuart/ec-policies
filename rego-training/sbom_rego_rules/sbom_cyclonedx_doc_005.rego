#
# METADATA
# title: Verify the CycloneDX SBOM has a valid specVersion format.
# description: >-
#   Verify the CycloneDX SBOM has a valid specVersion format.
# custom:
#   short_name: sbom_cyclonedx_doc_005
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_005

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    not contains(sbom.specVersion, ".")
    result := sprintf("CycloneDX SBOM has invalid specVersion format: %s", [sbom.specVersion])
}
