#
# METADATA
# title: Verify the CycloneDX SBOM has a specVersion.
# description: >-
#   Verify the CycloneDX SBOM has a specVersion.
# custom:
#   short_name: sbom_cyclonedx_doc_002
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_002

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    not sbom.specVersion
    result := "CycloneDX SBOM has no specVersion"
}
