#
# METADATA
# title: Verify all files in the SPDX SBOM have a fileName.
# description: >-
#   Verify all files in the SPDX SBOM have a fileName.
# custom:
#   short_name: sbom_spdx_file_001
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_001

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    not file.fileName
    result := "File in SPDX SBOM has no fileName"
}
