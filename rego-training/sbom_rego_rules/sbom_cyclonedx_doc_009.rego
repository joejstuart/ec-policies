#
# METADATA
# title: Verify the CycloneDX SBOM metadata timestamp is valid ISO 8601.
# description: >-
#   Verify the CycloneDX SBOM metadata timestamp is valid ISO 8601.
# custom:
#   short_name: sbom_cyclonedx_doc_009
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_009

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    sbom.metadata.timestamp
    not contains(sbom.metadata.timestamp, "T")
    result := sprintf("CycloneDX SBOM metadata timestamp is not valid ISO 8601: %s", [sbom.metadata.timestamp])
}
