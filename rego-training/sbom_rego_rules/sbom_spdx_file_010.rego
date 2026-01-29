#
# METADATA
# title: Verify all files in the SPDX SBOM have unique SPDXIDs.
# description: >-
#   Verify all files in the SPDX SBOM have unique SPDXIDs.
# custom:
#   short_name: sbom_spdx_file_010
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_010

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    file_ids := {file.SPDXID | some file in sbom.files}
    count(file_ids) != count(sbom.files)
    result := "SPDX SBOM has duplicate file SPDXIDs"
}
