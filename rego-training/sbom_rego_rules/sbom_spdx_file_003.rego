#
# METADATA
# title: Verify all files in the SPDX SBOM have checksums.
# description: >-
#   Verify all files in the SPDX SBOM have checksums.
# custom:
#   short_name: sbom_spdx_file_003
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_003

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    count(file.checksums) == 0
    result := sprintf("File %s has no checksums", [file.fileName])
}
