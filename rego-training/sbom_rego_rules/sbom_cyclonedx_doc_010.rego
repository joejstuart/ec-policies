#
# METADATA
# title: Verify all tools in the CycloneDX SBOM metadata have a vendor.
# description: >-
#   Verify all tools in the CycloneDX SBOM metadata have a vendor.
# custom:
#   short_name: sbom_cyclonedx_doc_010
#   failure_msg: Policy validation failed
#
package sbom_cyclonedx_doc_010

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://cyclonedx.org/bom"
    sbom := statement.predicate
    some tool in sbom.metadata.tools
    not tool.vendor
    result := sprintf("Tool %s in CycloneDX SBOM metadata has no vendor", [tool.name])
}
