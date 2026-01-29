#
# METADATA
# title: Verify all files in the SPDX SBOM have fileName starting with '/'.
# description: >-
#   Verify all files in the SPDX SBOM have fileName starting with '/'.
# custom:
#   short_name: sbom_spdx_file_009
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_009

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    not startswith(file.fileName, "/")
    result := sprintf("File %s does not start with /", [file.fileName])
}
