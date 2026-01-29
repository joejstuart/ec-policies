#
# METADATA
# title: Verify all files in the SPDX SBOM have a non-empty SPDXID.
# description: >-
#   Verify all files in the SPDX SBOM have a non-empty SPDXID.
# custom:
#   short_name: sbom_spdx_file_014
#   failure_msg: Policy validation failed
#
package sbom_spdx_file_014

import rego.v1

deny contains result if {
    some att in input.attestations
    statement := att.statement
    statement.predicateType == "https://spdx.dev/Document"
    sbom := statement.predicate
    some file in sbom.files
    file.SPDXID == ""
    result := sprintf("File %s has empty SPDXID", [file.fileName])
}
