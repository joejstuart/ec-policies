#
# METADATA
# title: Verify the SPDX SBOM has a valid spdxVersion.
# description: >-
#   Verify the SPDX SBOM has a valid spdxVersion.
# custom:
#   short_name: sbom_spdx_doc_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_doc_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    sbom.spdxVersion != "SPDX-2.3"
    result := sprintf("SPDX SBOM has invalid version: %s", [sbom.spdxVersion])
}
