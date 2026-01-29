#
# METADATA
# title: Verify the SPDX SBOM has a valid SPDXID.
# description: >-
#   Verify the SPDX SBOM has a valid SPDXID.
# custom:
#   short_name: sbom_spdx_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    sbom.SPDXID != "SPDXRef-DOCUMENT"
    result := sprintf("SPDX SBOM has invalid SPDXID: %s", [sbom.SPDXID])
}
