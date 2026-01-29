#
# METADATA
# title: Verify all files in the SPDX SBOM have unique fileNames.
# description: >-
#   Verify all files in the SPDX SBOM have unique fileNames.
# custom:
#   short_name: sbom_spdx_file_011
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_011

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    file_names := {file.fileName | some file in sbom.files}
    count(file_names) != count(sbom.files)
    result := "SPDX SBOM has duplicate file names"
}
